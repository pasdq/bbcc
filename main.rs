use std::env;  // 导入标准库模块，用于处理命令行参数
use std::fs::File;  // 用于处理文件操作
use std::io::{ self, BufRead };  // 用于标准输入/输出操作
use std::collections::HashMap;  // 用于定义哈希表(HashMap)数据结构
use evalexpr::*;  // 引入 evalexpr 库，用于计算表达式
use lazy_static::lazy_static;  // 引入 lazy_static 宏，允许在运行时初始化静态变量
use std::sync::Mutex;  // 用于多线程环境下的数据同步和互斥锁
use regex::Regex;  // 引入正则表达式库
use notify::{ Watcher, RecursiveMode, RecommendedWatcher, Event, EventKind };  // 用于文件系统通知的库，监控文件的更改
use std::sync::mpsc::channel;  // 多线程下的消息传递通道
use std::path::Path;  // 处理文件路径
use std::sync::atomic::{ AtomicBool, Ordering };  // 原子布尔值，用于线程间共享状态
use std::sync::Arc;  // 原子引用计数，用于在多线程环境下共享数据
use std::process::Command;  // 执行外部命令
use num_format::{ Locale, ToFormattedString };  // 数字格式化库，用于格式化输出

// 使用 lazy_static 宏定义全局静态变量 PRECISION，用 Mutex 包裹以实现线程安全，默认小数精度为4
lazy_static! {  
    static ref PRECISION: Mutex<usize> = Mutex::new(4); // 设置全局小数精度为 4  
}  

// 程序入口函数
fn main() {  
    let args: Vec<String> = env::args().collect();  // 获取命令行参数并收集到 args 向量中
    if args.len() < 2 {  // 检查参数数量是否足够
        eprintln!("Usage: {} [-r] <filename>", args[0]);  // 提示用法错误
        return;  
    }  

    let filename: &str;  // 定义文件名
    let mut watch_mode = false;  // 定义是否启用监视模式的布尔变量

    // 检查是否启用监视模式（-r 参数）
    if args.len() == 3 && args[1] == "-r" {  
        watch_mode = true;  
        filename = &args[2];  
    } else {  
        filename = &args[1];  
    }  

    if watch_mode {  
        clear_screen();  // 清空屏幕
        // 处理文件并监视其变化
        if let Err(e) = process_file(filename) {  
            eprintln!("Error: {}", e);  
        }  
        if let Err(e) = watch_file(Path::new(filename)) {  
            eprintln!("Error: {}", e);  
        }  
    } else {  
        if let Err(e) = process_file(filename) {  
            eprintln!("Error: {}", e);  
        }  
    }  
}

// 清空屏幕的函数
fn clear_screen() {  
    if cfg!(target_os = "windows") {  // 如果目标操作系统是 Windows
        let _ = Command::new("cmd").args(&["/C", "cls"]).status();  // 执行 cls 命令
    } else {  // 其他操作系统
        let _ = Command::new("clear").status();  // 执行 clear 命令
    }  
}

// 文件监视函数，使用 notify 库
fn watch_file(path: &Path) -> notify::Result<()> {  
    let (tx, rx) = channel();  // 创建一个通道用于接收文件更改事件
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {  
        tx.send(res).unwrap();  // 将事件发送到通道
    })?;  

    let running = Arc::new(AtomicBool::new(true));  // 创建一个原子布尔值用于控制程序运行
    let r = running.clone();  

    // 设置 Ctrl-C 信号的处理程序，当用户按下 Ctrl-C 时将 running 设为 false
    ctrlc::set_handler(move || {  
        r.store(false, Ordering::SeqCst);  
    }).expect("Error setting Ctrl-C handler");  

    watcher.watch(path, RecursiveMode::NonRecursive)?;  // 开始监视文件

    while running.load(Ordering::SeqCst) {  
        if let Ok(res) = rx.recv_timeout(std::time::Duration::from_millis(500)) {  // 以500毫秒的超时时间等待文件变化事件
            match res {  
                Ok(Event { kind: EventKind::Modify(..), .. }) => {  // 当文件被修改时
                    clear_screen();  
                    if let Err(e) = process_file(path.to_str().unwrap()) {  
                        eprintln!("Error: {}", e);  
                    }  
                }  
                Ok(_) => {}  // 其他事件忽略
                Err(e) => eprintln!("Watch error: {:?}", e),  // 错误处理
            }  
        }  
        if !running.load(Ordering::SeqCst) {  // 检查运行状态，退出监视
            println!("Exiting file watch...");  
            break;  
        }  
    }  
    Ok(())  
}

// 计算表达式或求解线性方程的函数
fn evaluate_expression(expr: &str, variables: &HashMap<String, String>) -> Result<String, String> {  
    if let Some((lhs, rhs)) = expr.split_once('=') {  
        solve_linear_equation(lhs, rhs, variables)  // 如果表达式包含 '=', 则求解线性方程
    } else {  
        evaluate_simple_expression(expr, variables)  // 否则，计算简单表达式
    }  
}

// 计算简单表达式
fn evaluate_simple_expression(  
    expr: &str,  
    variables: &HashMap<String, String>  
) -> Result<String, String> {  
    let mut replaced_expr = expr.to_string();  
    for (key, value) in variables {  
        replaced_expr = replaced_expr.replace(key, value);  // 替换变量
    }  
    let replaced_expr = replaced_expr.replace("%", "/100.0");  // 将百分号替换为对应计算
    let adjusted_expr = replaced_expr.replace("/", "*1.0/");  // 确保除法使用浮点数计算

    match eval(&adjusted_expr) {  // 计算表达式
        Ok(Value::Float(number)) => {  
            let precision = *PRECISION.lock().unwrap();  // 获取小数精度
            let formatted = format!("{:.precision$}", number, precision = precision)  // 格式化浮点数
                .trim_end_matches('0')  
                .trim_end_matches('.')  
                .to_string();  
            
            if let Some(integer_part) = formatted.split('.').next() {  
                if let Ok(parsed_number) = integer_part.parse::<i64>() {  
                    if parsed_number > 999 {  
                        let formatted_integer = parsed_number.to_formatted_string(&Locale::en);  
                        let rest = formatted.split('.').nth(1).unwrap_or("");  
                        if rest.is_empty() {  
                            Ok(formatted_integer)  
                        } else {  
                            Ok(format!("{}.{}", formatted_integer, rest))  
                        }  
                    } else {  
                        Ok(formatted)  
                    }  
                } else {  
                    Ok(formatted)  
                }  
            } else {  
                Ok(formatted)  
            }  
        }  
        Ok(Value::Int(number)) => {  
            if number > 999 {  
                Ok(number.to_formatted_string(&Locale::en))  // 大于 999 的整数进行千分位格式化
            } else {  
                Ok(format!("{}", number))  
            }  
        }  
        Ok(result) => Ok(result.to_string()),  
        Err(e) => Err(format!("Failed to evaluate expression '{}'. Error: {}", expr, e)),  
    }  
}

// 求解线性方程函数
fn solve_linear_equation(
    lhs: &str,
    rhs: &str,
    variables: &HashMap<String, String>
) -> Result<String, String> {
    let lhs_replaced = replace_variables(lhs.replace(" ", "").replace("X", "x"), variables);
    let rhs_replaced = replace_variables(rhs.replace(" ", "").replace("X", "x"), variables);

    if lhs_replaced.contains('x') || rhs_replaced.contains('x') {
        let x = "x";

        let lhs_value = eval(&replace_percentage(&lhs_replaced.replace(x, "0.0"))).map_err(|_|
            "Error evaluating LHS".to_string()
        )?;
        let rhs_value = eval(&replace_percentage(&rhs_replaced.replace(x, "0.0"))).map_err(|_|
            "Error evaluating RHS".to_string()
        )?;

        let coefficient = eval(&replace_percentage(&lhs_replaced.replace(x, "1.0"))).map_err(|_|
            "Error evaluating coefficient".to_string()
        )?;

        let lhs_value_num = lhs_value.as_number().map_err(|_| "LHS is not a number".to_string())?;
        let rhs_value_num = rhs_value.as_number().map_err(|_| "RHS is not a number".to_string())?;
        let coefficient_num =
            coefficient.as_number().map_err(|_| "Coefficient is not a number".to_string())? -
            lhs_value_num;

        if coefficient_num == 0.0 {
            return Err(
                "Invalid equation: coefficient of x is zero or not a linear equation".to_string()
            );
        }

        let result = (rhs_value_num - lhs_value_num) / coefficient_num;

        if result.fract() == 0.0 {
            let result_int = result as i64;
            if result_int > 999 {
                Ok(result_int.to_formatted_string(&Locale::en))
            } else {
                Ok(format!("{}", result_int))
            }
        } else {
            let precision = *PRECISION.lock().unwrap();
            let formatted_result = format!("{:.precision$}", result, precision = precision)
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_string();

            if let Some(integer_part) = formatted_result.split('.').next() {
                if let Ok(parsed_number) = integer_part.parse::<i64>() {
                    if parsed_number > 999 {
                        let formatted_integer = parsed_number.to_formatted_string(&Locale::en);
                        let rest = formatted_result.split('.').nth(1).unwrap_or("");
                        if rest.is_empty() {
                            Ok(formatted_integer)
                        } else {
                            Ok(format!("{}.{}", formatted_integer, rest))
                        }
                    } else {
                        Ok(formatted_result)
                    }
                } else {
                    Ok(formatted_result)
                }
            } else {
                Ok(formatted_result)
            }
        }
    } else {
        Err("The equation does not contain variable 'x'".to_string())
    }
}
  
// 替换表达式中的变量
fn replace_variables(expr: String, variables: &HashMap<String, String>) -> String {  
    let mut replaced_expr = expr;  
    for (key, value) in variables {  
        replaced_expr = replaced_expr.replace(key, value);  // 用变量的值替换表达式中的变量
    }  
    replaced_expr  
}  
  
// 替换百分号为计算表达式
fn replace_percentage(expr: &str) -> String {  
    expr.replace("%", "/100.0")  
}  
  
// 处理包含表达式的文本行
fn process_text_with_expressions(line: &str, variables: &HashMap<String, String>) -> String {  
    let re = Regex::new(r"\{([^}]*)\}").unwrap();  // 创建用于匹配 {} 内部表达式的正则表达式
  
    let result = re.replace_all(line, |caps: &regex::Captures| {  
        let expr = &caps[1];  // 提取表达式
        match evaluate_expression(expr, variables) {  
            Ok(result) => result,  // 计算表达式并替换
            Err(err_msg) => format!("{{Error: {}}}", err_msg),  // 如果出错，替换为错误信息
        }  
    });  
  
    result.to_string()  
}  
  
// 处理文件中的每一行
fn process_file(filename: &str) -> io::Result<()> {  
    let file = File::open(filename)?;  // 打开文件
    let reader = io::BufReader::new(file);  // 创建缓冲读取器
  
    let mut variables: HashMap<String, String> = HashMap::new();  // 定义变量存储的哈希表
  
    for line in reader.lines() {  
        let line = line?;  
        let line = line.trim();  // 去除空白字符
  
        // 去除行中的注释部分
        let line = if let Some((code, _comment)) = line.split_once("//") {  
            code.trim()  
        } else {  
            line  
        };  
  
        if line.is_empty() {  
            continue;  // 跳过空行
        }  
  
        // 处理变量赋值语句
        if let Some((key, value)) = line.split_once(":=") {  
            let key = key.trim();  
            let value = value.trim();  
  
            match evaluate_expression(value, &variables) {  
                Ok(result) => {  
                    variables.insert(key.to_string(), result);  // 将结果存储到变量表中
                }  
                Err(err_msg) => {  
                    eprintln!(  
                        "Error: Could not evaluate expression '{}'. Reason: {}",  
                        value,  
                        err_msg  
                    );  
                }  
            }  
        } else {  
            let output = process_text_with_expressions(line, &variables);  // 处理文本行中的表达式
            println!("{}", output);  // 输出结果
        }  
    }  
  
    Ok(())  
}  

