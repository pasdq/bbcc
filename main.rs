use colored::*; //终端颜色设置
use std::env; // 处理命令行参数
use std::fs::File; // 处理文件操作
use std::io::{ self, BufRead }; // 标准输入/输出操作
use std::collections::HashMap; // 定义哈希表数据结构
use evalexpr::*; // 引入 evalexpr 库，用于计算表达式
use lazy_static::lazy_static; // 引入 lazy_static 宏，运行时初始化静态变量
use std::sync::Mutex; // 多线程互斥锁
use regex::Regex; // 正则表达式库
use notify::{ Watcher, RecursiveMode, RecommendedWatcher, Event, EventKind }; // 文件系统通知，监控文件更改
use std::sync::mpsc::channel; // 多线程消息通道
use std::path::Path; // 处理文件路径
use std::sync::atomic::{ AtomicBool, Ordering }; // 原子布尔值，线程间共享状态
use std::sync::Arc; // 原子引用计数，共享数据
use std::process::Command; // 执行外部命令
use num_format::{ Locale, ToFormattedString }; // 数字格式化库

// 全局静态变量 PRECISION，用于控制小数精度，线程安全
lazy_static! {
    static ref PRECISION: Mutex<usize> = Mutex::new(4); // 设置小数精度为4
    static ref EXPRESSION_REGEX: Regex = Regex::new(r"\[([^\]]*)\]").unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect(); // 获取命令行参数
    if args.len() < 2 {
        // 参数不足时提示用法错误
        eprintln!("Usage: {} [-r | -p] <filename>", args[0]);
        return;
    }

    let mut watch_mode = false; // 是否监视文件模式
    let mut pipe_mode = false; // 是否从管道接收数据模式
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
        if let Err(e) = process_from_stdin() {
            // 从管道读取数据
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
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("cmd").args(&["/C", "cls"]).status();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("clear").status();
    }
}

// 文件监视函数
fn watch_file(path: &Path) -> notify::Result<()> {
    let (tx, rx) = channel(); // 创建通道接收文件变更事件
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        tx.send(res).unwrap();
    })?;

    let running = Arc::new(AtomicBool::new(true)); // 原子布尔值控制程序运行状态
    let r = running.clone();

    // Ctrl-C 信号处理器，当用户按下 Ctrl-C 时，停止监视
    ctrlc
        ::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");

    watcher.watch(path, RecursiveMode::NonRecursive)?; // 开始监视文件

    while running.load(Ordering::SeqCst) {
        if let Ok(res) = rx.recv_timeout(std::time::Duration::from_millis(500)) {
            match res {
                Ok(Event { kind: EventKind::Modify(..), .. }) => {
                    clear_screen();
                    if let Err(e) = process_file(path.to_str().unwrap()) {
                        eprintln!("Error: {}", e);
                    }
                    println!(
                        "\n- Monitoring changes to {} in real-time.\n- https://github.com/pasdq\n- V1.0.0",
                        path.display()
                    );
                }
                Ok(_) => {} // 忽略其他事件
                Err(e) => eprintln!("Watch error: {:?}", e), // 错误处理
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
    let reader = stdin.lock(); // 锁定标准输入
    process_lines(reader) // 处理输入的每一行
}

// 处理文件内容
fn process_file(filename: &str) -> io::Result<()> {
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    process_lines(reader)
}

// 处理输入行的函数
fn process_lines<R: BufRead>(reader: R) -> io::Result<()> {
    let mut variables: HashMap<String, String> = HashMap::new(); // 已计算的变量值
    let mut raw_variables: HashMap<String, String> = HashMap::new(); // 存储原始的变量值

    for line in reader.lines() {
        let line = line?;
        let original_line = line.replace("\t", "    ");

        let line = if let Some((code, _comment)) = original_line.split_once("//") {
            code
        } else {
            &original_line
        };

        if line.is_empty() {
            continue;
        }

        let trimmed_line = line.trim_start();

        if trimmed_line.starts_with('#') {
            let line = trimmed_line.trim_start_matches('#').trim();
            println!("{}", line);
            continue;
        }

        if trimmed_line.starts_with('!') {
            let expression = trimmed_line.trim_start_matches('!').trim();
            match evaluate_expression(expression, &variables) {
                Ok(result) => println!("{}", result),
                Err(err_msg) => eprintln!("Error: {}", err_msg),
            }
            continue;
        }

        if trimmed_line.starts_with("---") {
            println!();
            continue;
        }

        if let Some((key, value)) = line.split_once(":=") {
            let key = key.trim();
            let value = value.trim();

            // 存储原始表达式值
            raw_variables.insert(key.to_string(), value.to_string());

            match evaluate_expression(value, &variables) {
                Ok(result) => {
                    variables.insert(key.to_string(), result);
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
            let output = process_text_with_expressions(&original_line, &variables, &raw_variables);
            println!("{}", output);
        }
    }

    Ok(())
}

// 计算表达式或求解线性方程
fn evaluate_expression(expr: &str, variables: &HashMap<String, String>) -> Result<String, String> {
    // 检查表达式是否为条件表达式
    if expr.starts_with("{if") && expr.ends_with('}') {
        let condition_expr = &expr[1..expr.len() - 1]; // 去掉大括号
	let if_regex = Regex::new(r"(?i)if\s+(.+?)\s+then\s+(.+?)(?:\s+else\s+(.+))?$").unwrap();

        if let Some(caps) = if_regex.captures(condition_expr) {
            let condition = &caps[1];
            let then_value = &caps[2];
            let else_value = caps.get(3).map_or("", |m| m.as_str());

            // 解析条件
            let condition_result = evaluate_condition(condition, variables);

            // 根据条件结果返回 then 或 else 部分
            if condition_result {
                return evaluate_expression(then_value, variables);
            } else {
                return evaluate_expression(else_value, variables);
            }
        } else {
            return Err("Invalid conditional expression".to_string());
        }
    }

    // 原有的表达式处理逻辑
    let clean_expr = if expr.starts_with('[') && expr.ends_with(']') {
        &expr[1..expr.len() - 1]
    } else {
        expr
    };

    // 新增逻辑：如果 clean_expr 是一个变量名，直接返回其值
    if let Some(value) = variables.get(clean_expr) {
        return Ok(value.clone());
    }

    if
        (clean_expr.starts_with('"') && clean_expr.ends_with('"')) ||
        (clean_expr.starts_with('\'') && clean_expr.ends_with('\''))
    {
        let value = clean_expr.trim_matches(|c| (c == '"' || c == '\'')).to_string();
        Ok(value)
    } else if let Some((lhs, rhs)) = clean_expr.split_once('=') {
        solve_linear_equation(lhs, rhs, variables)
    } else {
        evaluate_simple_expression(clean_expr, variables)
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
    // 如果表达式本身是一个变量名，且该变量的值是字符串，直接返回该变量值
    if let Some(value) = variables.get(expr) {
        if
            (value.starts_with('"') && value.ends_with('"')) ||
            (value.starts_with('\'') && value.ends_with('\''))
        {
            // 如果变量是字符串，直接返回其值去掉引号（双引号或单引号）
            return Ok(value.trim_matches(|c| (c == '"' || c == '\'')).to_string());
        }
        return Ok(value.to_string());
    }

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
                Ok(number.to_formatted_string(&Locale::en)) // 大于 999 的整数进行格式化
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
        let cleaned_value = value.replace(",", "");
        replaced_expr = replaced_expr.replace(key, &cleaned_value);
    }
    replaced_expr
}

// 处理包含表达式的文本行
fn process_text_with_expressions(
    line: &str,
    variables: &HashMap<String, String>,
    raw_variables: &HashMap<String, String>
) -> String {
    let if_regex = Regex::new(
	r"(?i)\{if\s+([^\}]+?)\s+then\s+([^\}]+?)(?:\s+else\s+([^\}]+?))?\}",
    ).unwrap();
    let result = if_regex.replace_all(line, |caps: &regex::Captures| {
        let condition = &caps[1].trim();
        let then_value = &caps[2].trim();
        let else_value = caps.get(3).map_or("null", |m| m.as_str().trim());

        let condition_result = evaluate_condition(condition, variables);

        if condition_result {
            evaluate_then_or_else(then_value, variables)
        } else {
            evaluate_then_or_else(else_value, variables)
        }
    });

    // 处理 $[...]，直接取出原始值并替换 *
    let result = Regex::new(r"\$\[([^\]]*)\]")
        .unwrap()
        .replace_all(&result, |caps: &regex::Captures| {
            let var_name = &caps[1];
            let default_value = String::new(); // 创建一个持久的String值，避免临时性
            let expression = raw_variables.get(var_name).unwrap_or(&default_value); // 使用持久的String值，而不是临时值

            // 替换变量名为实际的值
            let mut expression_with_values = replace_variables(expression.to_string(), variables);

            // 使用正则表达式来确保运算符前后有且仅有一个空格
            let operator_regex = Regex::new(r"\s*([+\-*/])\s*").unwrap();
            expression_with_values = operator_regex
                .replace_all(&expression_with_values, " $1 ")
                .to_string();

            // 替换 * 为 x
            expression_with_values = expression_with_values.replace("*", "x");

            expression_with_values
        });

    let result = EXPRESSION_REGEX.replace_all(&result, |caps: &regex::Captures| {
        let expr = &caps[1];
        match evaluate_expression(expr, variables) {
            Ok(result) => highlight_numbers(&result),
            Err(err_msg) => format!("[Error: {}]", err_msg),
        }
    });

    let result_with_color = highlight_parentheses(result.to_string());
    let final_result = highlight_special_chars(result_with_color);

    highlight_currency(highlight_keywords(final_result))
}

// 新增函数 evaluate_then_or_else 用来区分处理 [] 和 "" 包裹的值
fn evaluate_then_or_else(value: &str, variables: &HashMap<String, String>) -> String {
    let mut result = String::new();
    let mut remaining = value;

    while let Some(start_bracket) = remaining.find("[") {
        if let Some(end_bracket) = remaining[start_bracket..].find("]") {
            let expression = &remaining[start_bracket + 1..start_bracket + end_bracket];
            let expr_result = evaluate_expression(expression, variables).unwrap_or_else(|_| "[Error]".to_string());

            result.push_str(&remaining[..start_bracket]);
            result.push_str(&expr_result);

            remaining = &remaining[start_bracket + end_bracket + 1..];
        } else {
            break;
        }
    }

    result.push_str(remaining);

    if result.is_empty() {
        result = value.to_string();
    }

    // 去掉结果两端的引号
    result.trim_matches(|c| c == '"' || c == '\'').to_string()
}

// 新增一个函数 evaluate_condition 来处理条件判断
fn evaluate_condition(condition: &str, variables: &HashMap<String, String>) -> bool {
    // 去除条件两端的空格
    let mut condition = condition.trim().to_string();

    // 处理 `[]` 表达式
    if let Some(caps) = EXPRESSION_REGEX.captures(&condition) {
        let inner_expr = &caps[1];
        if let Ok(result) = evaluate_expression(inner_expr, variables) {
            condition = condition.replace(&format!("[{}]", inner_expr), &result);
        } else {
            return false; // 如果计算失败，返回 false
        }
    }

    // 移除条件中的千位分隔符
    condition = replace_commas(condition);

    // 支持基本的条件运算符
    if condition.contains(">=") {
        let parts: Vec<&str> = condition.split(">=").collect();
        return parse_value(&replace_commas(parts[0].to_string()), variables).parse::<f64>().unwrap_or(0.0) >=
               parse_value(&replace_commas(parts[1].to_string()), variables).parse::<f64>().unwrap_or(0.0);
    } else if condition.contains("<=") {
        let parts: Vec<&str> = condition.split("<=").collect();
        return parse_value(&replace_commas(parts[0].to_string()), variables).parse::<f64>().unwrap_or(0.0) <=
               parse_value(&replace_commas(parts[1].to_string()), variables).parse::<f64>().unwrap_or(0.0);
    } else if condition.contains(">") {
        let parts: Vec<&str> = condition.split(">").collect();
        return parse_value(&replace_commas(parts[0].to_string()), variables).parse::<f64>().unwrap_or(0.0) >
               parse_value(&replace_commas(parts[1].to_string()), variables).parse::<f64>().unwrap_or(0.0);
    } else if condition.contains("<") {
        let parts: Vec<&str> = condition.split("<").collect();
        return parse_value(&replace_commas(parts[0].to_string()), variables).parse::<f64>().unwrap_or(0.0) <
               parse_value(&replace_commas(parts[1].to_string()), variables).parse::<f64>().unwrap_or(0.0);
    } else if condition.contains("==") {
        let parts: Vec<&str> = condition.split("==").collect();
        return parse_value(&replace_commas(parts[0].to_string()), variables).parse::<f64>().unwrap_or(0.0) ==
               parse_value(&replace_commas(parts[1].to_string()), variables).parse::<f64>().unwrap_or(0.0);
    } else if condition.contains("!=") {
        let parts: Vec<&str> = condition.split("!=").collect();
        return parse_value(&replace_commas(parts[0].to_string()), variables).parse::<f64>().unwrap_or(0.0) !=
               parse_value(&replace_commas(parts[1].to_string()), variables).parse::<f64>().unwrap_or(0.0);
    }

    // 如果条件是一个简单的变量或布尔值，处理它
    let value = parse_value(&replace_commas(condition.to_string()), variables);
    value != "0" && value.to_lowercase() != "false"
}

// 解析变量和表达式的辅助函数 parse_value
fn parse_value(expression: &str, variables: &HashMap<String, String>) -> String {
    let trimmed_expr = expression.trim();
    if let Some(value) = variables.get(trimmed_expr) {
        return value.replace(",", ""); // 删除逗号
    } else {
        return trimmed_expr.to_string();
    }
}

// 新增的函数，用于将括号及其内容显示为蓝色
fn highlight_parentheses(text: String) -> String {
    let paren_regex = Regex::new(r"\((.*?)\)").unwrap();
    paren_regex
        .replace_all(&text, |caps: &regex::Captures| {
            // 使用 to_string() 方法将 str 类型转换为 String 类型
            format!("{}", format!("({})", caps[1].to_string()).green())
        })
        .to_string()
}

fn highlight_numbers(text: &str) -> String {
    // 修改正则表达式，匹配千位分隔符的数字
    let number_regex = Regex::new(r"(\d{1,3}(,\d{3})*(\.\d+)?)").unwrap();
    number_regex
        .replace_all(text, |caps: &regex::Captures| {
            // 将整个数字（包括千位分隔符）设置为绿色
            format!("{}", caps[0].red())
        })
        .to_string()
}

// 处理特殊符号，使其显示为黄色
fn highlight_special_chars(text: String) -> String {
    let special_chars_regex = Regex::new(r"[%$@|\-=:<>]").unwrap(); // 正确匹配 %$@|\-=:<>
    special_chars_regex
        .replace_all(&text, |caps: &regex::Captures| { format!("{}", caps[0].yellow()) })
        .to_string()
}

// 新增函数，用于高亮 let, find, solve 关键字
fn highlight_keywords(text: String) -> String {
    let keywords_regex = Regex::new(r"(?i)\b(let|find|solve|已知|求解)\b").unwrap(); // (?i) 表示不区分大小写
    keywords_regex
        .replace_all(&text, |caps: &regex::Captures| {
            format!("{}", caps[0].blue()) // 将关键词设置为蓝色
        })
        .to_string()
}

fn highlight_currency(text: String) -> String {
    let currency_regex = Regex::new(r"(?i)\b(USD|HKD|CNY|RMB|Error.*)\b").unwrap(); // (?i) 表示不区分大小写
    currency_regex
        .replace_all(&text, |caps: &regex::Captures| {
            format!("{}", caps[0].yellow()) // 将关键词设置为红色
        })
        .to_string()
}

// 求解线性方程的函数
fn solve_linear_equation(
    lhs: &str,
    rhs: &str,
    variables: &HashMap<String, String>
) -> Result<String, String> {
    let lhs_replaced = replace_commas(
        replace_variables(lhs.replace(" ", "").replace("X", "x"), variables)
    );
    let rhs_replaced = replace_commas(
        replace_variables(rhs.replace(" ", "").replace("X", "x"), variables)
    );

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

// 替换百分号为计算表达式
fn replace_percentage(expr: &str) -> String {
    expr.replace("%", "/100.0")
}
