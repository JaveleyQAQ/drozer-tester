# drozer-tester
Bash script for automated testing of the drozer component used in penetration testing. 

## drozer 自动化测试脚本🤖️
> 半自动化把，`expect`脚本不太灵活，`activity`启动基于正则匹配，可能会漏掉，有错误记得提问题😊



![image](https://github.com/JaveleyQAQ/drozer-tester/assets/132129852/9b1fab71-4c75-4eaf-9b68-c27d2adc680b)

### ✅安装并运行
```bash
curl -LO https://raw.githubusercontent.com/JaveleyQAQ/drozer-tester/main/drozer-tester.sh && chmod +x drozer-tester.sh && ./drozer-tester.sh
```

### 🔥使用方法：


- 扫描单个程序：
```bash
 chmod +x ./drozer-tester.sh 
 expect ./drozer-tester.sh  jakhar.aseem.diva
 ```
或者

```bash
./drozer-tester.sh  jakhar.aseem.diva
 ```
- 批量扫描
```expect
expect ./drozer-tester.sh  all
```

[![asciicast](https://asciinema.org/a/591669.svg)](https://asciinema.org/a/591669)

![image](https://github.com/JaveleyQAQ/drozer-tester/assets/132129852/082cc657-7f5e-4131-a4f2-1fc1279bf4ae)


- 日志文件会在运行目录下生成`drozer-tester`文件夹📁

  ![image](https://github.com/JaveleyQAQ/drozer-tester/assets/132129852/a73fc79f-dd58-42f7-bb9b-acf330fe89c3)
  ![image](https://github.com/JaveleyQAQ/drozer-tester/assets/132129852/15a77e40-fa9c-413f-9dbf-7880148cddfc)
  ![image](https://github.com/JaveleyQAQ/drozer-tester/assets/132129852/ac468723-ab5c-4c00-b5e4-e2594016af26)

