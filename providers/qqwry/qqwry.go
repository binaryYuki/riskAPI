package main

// 占位文件：原先此处存在与根目录 qqwry.go 重复的纯真(QQWry)实现。
// 为避免函数/类型/常量重复定义导致的编译冲突，逻辑已统一集中到项目根目录的 qqwry.go。
//
// 现保留此文件仅用于：
// 1. 文档说明与溯源（数据库文件仍位于 providers/qqwry/qqwry.dat）
// 2. 未来若需要拆分为独立包，可在此重新引出封装接口。
//
// 访问接口：直接调用 QueryQQWryIP / GetQQWryStats。
// 数据库初始化：首次调用时自动通过 InitQQWryDatabase() 完成。
//
// 如果后续需要包级封装，可将根目录实现迁移到 providers/qqwry 并改为 package qqwry，然后在主程序 import。
