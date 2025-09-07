package qqwry

// 占位文件：原先此处存在与根目录 qqwry.go 重复的纯真(QQWry)实现。
// 为避免函数/类型/常量重复定义导致的编译冲突，逻辑已统一集中到项目根目录的 qqwry.go。
//
// 当前本目录仅存放数据库文件 qqwry.dat 以及将来可能的独立封装。
// 若未来需要将实现迁移到库包，可：
// 1. 把根目录实现移动到本目录；
// 2. 改为 `package qqwry` 并导出所需 API；
// 3. 在主程序中 `import "risky_ip_filter/providers/qqwry"` 使用。
//
// 之所以保留该占位文件，是为了让 `providers/qqwry` 目录在 go modules 中被视为一个普通库包（而非意外的 `package main`）。
