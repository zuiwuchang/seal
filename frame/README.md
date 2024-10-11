# frame

這裏定義了一種簡單快速的 frame 編碼方案，目的在於序列化數據以便存儲或通過網路存儲

frame 由三部分組成


- **id** uint8 uint16 uint32 uint64 數據 id，雙方使用 id 識別數據是什麼
- **flag** 此字節最高的 1bit 如果爲 0 表示只有一個 payload
- **payload**  7bit+不定長度，記錄了實際數據載荷

flag+payload 數量是不定的

```
id + 0 + payload

id + 1 + payload, + 1 + payload, ...,  0 + payload
```