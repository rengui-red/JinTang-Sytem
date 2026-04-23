-- /etc/nginx/lua/waf.lua
-- 金汤 WAF 核心脚本

local _M = {}

-- 定义 SQL 注入特征规则 (正则表达式)
local rules = {
    -- 联合查询注入
    "union.*select",
    -- 基本的 Select 语句
    "select.*from",
    -- 信息架构探测
    "information_schema",
    -- 常见函数注入
    "sleep\\s*\\(",
    "benchmark\\s*\\(",
    "load_file\\s*\\(",
    "into\\s+outfile",
    -- 注释符攻击
    "/\\*",
    "--",
    -- 逻辑绕过
    "'\\s*or\\s*'?\\d*'?\\s*=\\s*'?\\d*",
    "'\\s*and\\s*'?\\d*'?\\s*=\\s*'?\\d*"
}

-- 获取请求参数
local function get_args()
    local args = ngx.req.get_uri_args()
    local all_args = {}
    
    for k, v in pairs(args) do
        if type(v) == "table" then
            for _, val in ipairs(v) do
                table.insert(all_args, val)
            end
        else
            table.insert(all_args, v)
        end
    end
    return all_args
end

-- 执行检测
local function check_waf()
    local args = get_args()
    
    for _, arg_val in ipairs(args) do
        -- 1. URL 解码 (防止 %27 绕过)
        local decoded_val = ngx.unescape_uri(arg_val)
        
        -- 2. 转小写 (防止 UNION SELECT 绕过)
        local lower_val = string.lower(decoded_val)
        
        -- 3. 匹配规则
        for _, rule in ipairs(rules) do
            if string.match(lower_val, rule) then
                -- 记录日志
                ngx.log(ngx.ERR, "Jin-Tang WAF Alert: SQL Injection detected! Param: ", arg_val, " Rule: ", rule)
                
                -- 设置 Nginx 变量用于日志记录
                ngx.var.waf_action = "BLOCKED_SQLI"
                
                -- 阻断请求
                ngx.exit(403)
                return
            end
        end
    end
end

-- 主入口
check_waf()