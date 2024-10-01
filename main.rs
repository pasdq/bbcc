use std::env;  // 处理命令行参数
use std::fs::File;  // 处理文件操作
use std::io::{self, BufRead};  // 标准输入/输出操作
use std::collections::HashMap;  // 定义哈希表数据结构
use evalexpr::*;  // 引入 evalexpr 库，用于计算表达式
use lazy_static::lazy_static;  // 引入 lazy_static 宏，运行时初始化静态变量
use std::sync::Mutex;  // 多线程互斥锁
use regex::Regex;  // 正则表达式库
use notify::{Watcher, RecursiveMode, RecommendedWatcher, Event, EventKind};  // 文件系统通知，监控文件更改
use std::sync::mpsc::channel;  // 多线程消息通道
use std::path::Path;  // 处理文件路径
use std::sync::atomic::{AtomicBool, Ordering};  // 原子布尔值，线程间共享状态
use std::sync::Arc;  // 原子引用计数，共享数据
use std::process::Command;  // 执行外部命令
use num_format::{Locale, ToFormattedString};  // 数字格式化库

// 全局静态变量 PRECISION，用于控制小数精度，线程安全
lazy_static! {
    static ref PRECISION: Mutex<usize> = Mutex::new(4);  // 设置小数精度为4
}

fn main() {
    let args: Vec<String> = env::args().collect();  // 获取命令行参数
    if args.len() < 2 {  // 参数不足时提示用法错误
        eprintln!("Usage: {} [-r | -p] <filename>", args[0]);
        return;
    }

    let mut watch_mode = false;  // 是否监视文件模式
    let mut pipe_mode = false;  // 是否从管道接收数据模式
    let filename: Option<&str>;

    // 检查命令行参数是否为 -r 或 -p
    if args[1] == "-r" && args.len() == 3 {
        watch_mode = true;
        filename = Some(&args[2]);
    } else if args[1] == "-p" {
        pipe_mode = true;
        filename = None;
    } else if args.len() == 2 {
        filename = Some(&args[1]);
    } else {
        eprintln!("Usage: {} [-r | -p] <filename>", args[0]);
        return;
    }

    if watch_mode {
        clear_screen();
        if let Some(file) = filename {
            if let Err(e) = process_file(file) {
                eprintln!("Error: {}", e);
            }
            if let Err(e) = watch_file(Path::new(file)) {
                eprintln!("Error: {}", e);
            }
        }
    } else if pipe_mode {
        if let Err(e) = process_from_stdin() {  // 从管道读取数据
            eprintln!("Error: {}", e);
        }
    } else if let Some(file) = filename {
        if let Err(e) = process_file(file) {
            eprintln!("Error: {}", e);
        }
    }
}

// 清空屏幕函数
fn clear_screen() {
    if cfg!(target_os = "windows") {
        let _ = Command::new("cmd").args(&["/C", "cls"]).status();  // Windows 使用 cls 清屏
    } else {
        let _ = Command::new("clear").status();  // Unix-like 系统使用 clear 清屏
    }
}

// 文件监视函数
fn watch_file(path: &Path) -> notify::Result<()> {
    let (tx, rx) = channel();  // 创建通道接收文件变更事件
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        tx.send(res).unwrap();
    })?;

    let running = Arc::new(AtomicBool::new(true));  // 原子布尔值控制程序运行状态
    let r = running.clone();

    // Ctrl-C 信号处理器，当用户按下 Ctrl-C 时，停止监视
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    watcher.watch(path, RecursiveMode::NonRecursive)?;  // 开始监视文件

    while running.load(Ordering::SeqCst) {
        if let Ok(res) = rx.recv_timeout(std::time::Duration::from_millis(500)) {
            match res {
                Ok(Event { kind: EventKind::Modify(..), .. }) => {
                    clear_screen();
                    if let Err(e) = process_file(path.to_str().unwrap()) {
                        eprintln!("Error: {}", e);
                    }
                    println!("------\nAwaiting the update of {} ...\nBBCC V1.0.0\n------", path.display());
                }
                Ok(_) => {}  // 忽略其他事件
                Err(e) => eprintln!("Watch error: {:?}", e),  // 错误处理
            }
        }
        if !running.load(Ordering::SeqCst) {
            println!("Exiting file watch...");
            break;
        }
    }
    Ok(())
}

// 从标准输入（管道）读取数据并处理
fn process_from_stdin() -> io::Result<()> {
    let stdin = io::stdin();
    let reader = stdin.lock();  // 锁定标准输入
    process_lines(reader)  // 处理输入的每一行
}

// 处理文件内容
fn process_file(filename: &str) -> io::Result<()> {
    let file = File::open(filename)?;  // 打开文件
    let reader = io::BufReader::new(file);  // 创建缓冲读取器
    process_lines(reader)  // 处理文件中的每一行
}

// 处理输入行的函数
fn process_lines<R: BufRead>(reader: R) -> io::Result<()> {
    let mut variables: HashMap<String, String> = HashMap::new();  // 用于存储变量的哈希表

    for line in reader.lines() {
        let line = line?;  // 读取行
        let line = line.trim();  // 去除空白字符

        let line = if let Some((code, _comment)) = line.split_once("//") {
            code.trim()  // 去除注释部分
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
                    variables.insert(key.to_string(), result);  // 将结果存储在变量表中
                }
                Err(err_msg) => {
                    eprintln!("Error: Could not evaluate expression '{}'. Reason: {}", value, err_msg);
                }
            }
        } else {
            let output = process_text_with_expressions(line, &variables);  // 处理表达式
            println!("{}", output);  // 输出结果
        }
    }

    Ok(())
}

// 计算表达式或求解线性方程
fn evaluate_expression(expr: &str, variables: &HashMap<String, String>) -> Result<String, String> {
    if let Some((lhs, rhs)) = expr.split_once('=') {
        solve_linear_equation(lhs, rhs, variables)  // 求解线性方程
    } else {
        evaluate_simple_expression(expr, variables)  // 计算简单表达式
    }
}

// 替换表达式中的千位分隔符
fn replace_commas(expr: String) -> String {
    expr.replace(",", "")
}

// 计算简单表达式
fn evaluate_simple_expression(
    expr: &str,
    variables: &HashMap<String, String>
) -> Result<String, String> {
    let replaced_expr = replace_variables(expr.to_string(), variables);
    let replaced_expr = replace_commas(replaced_expr);
    let replaced_expr = replaced_expr.replace("%", "/100.0");
    let adjusted_expr = replaced_expr.replace("/", "*1.0/");

    match eval(&adjusted_expr) {
        Ok(Value::Float(number)) => {
            let precision = *PRECISION.lock().unwrap();
            let formatted = format!("{:.precision$}", number, precision = precision)
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
                Ok(number.to_formatted_string(&Locale::en))  // 大于 999 的整数进行格式化
            } else {
                Ok(format!("{}", number))
            }
        }
        Ok(result) => Ok(result.to_string()),
        Err(e) => Err(format!("Failed to evaluate expression '{}'. Error: {}", expr, e)),
    }
}

// 替换表达式中的变量
fn replace_variables(expr: String, variables: &HashMap<String, String>) -> String {
    let mut replaced_expr = expr;
    for (key, value) in variables {
        let cleaned_value = value.replace(",", "");  // 删除千位分隔符
        replaced_expr = replaced_expr.replace(key, &cleaned_value);  // 替换变量
    }
    replaced_expr
}

// 处理包含表达式的文本行
fn process_text_with_expressions(line: &str, variables: &HashMap<String, String>) -> String {
    let re = Regex::new(r"\{([^}]*)\}").unwrap();  // 匹配 {} 内的表达式

    let result = re.replace_all(line, |caps: &regex::Captures| {
        let expr = &caps[1];
        match evaluate_expression(expr, variables) {
            Ok(result) => result,  // 替换为计算结果
            Err(err_msg) => format!("{{Error: {}}}", err_msg),  // 错误处理
        }
    });

    result.to_string()
}

// 求解线性方程的函数
fn solve_linear_equation(lhs: &str, rhs: &str, variables: &HashMap<String, String>) -> Result<String, String> {
    let lhs_replaced = replace_commas(replace_variables(lhs.replace(" ", "").replace("X", "x"), variables));
    let rhs_replaced = replace_commas(replace_variables(rhs.replace(" ", "").replace("X", "x"), variables));

    if lhs_replaced.contains('x') || rhs_replaced.contains('x') {
        let x = "x";

        let lhs_value = eval(&replace_percentage(&lhs_replaced.replace(x, "0.0"))).map_err(|_| "Error evaluating LHS".to_string())?;
        let rhs_value = eval(&replace_percentage(&rhs_replaced.replace(x, "0.0"))).map_err(|_| "Error evaluating RHS".to_string())?;

        let coefficient = eval(&replace_percentage(&lhs_replaced.replace(x, "1.0"))).map_err(|_| "Error evaluating coefficient".to_string())?;

        let lhs_value_num = lhs_value.as_number().map_err(|_| "LHS is not a number".to_string())?;
        let rhs_value_num = rhs_value.as_number().map_err(|_| "RHS is not a number".to_string())?;
        let coefficient_num = coefficient.as_number().map_err(|_| "Coefficient is not a number".to_string())? - lhs_value_num;

        if coefficient_num == 0.0 {
            return Err("Invalid equation: coefficient of x is zero or not a linear equation".to_string());
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

// 替换百分号为计算表达式
fn replace_percentage(expr: &str) -> String {
    expr.replace("%", "/100.0")
}
