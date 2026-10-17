---
name: 判定ルールの追加・修正
about: 「このサービスを判定できるようにしてほしい」という提案
title: "[ルール] "
labels: ["rules"]
assignees: []
---

## 追加・修正したい判定

- サービス名:
- 分類（メール / CMS / CDN・WAF など）:
- 見るレコード（NS / MX / TXT / CNAME / PTR / HTTP）:

## 判定に使える文字列の根拠

<!-- 例: MX レコードに example-mail.jp が含まれる、など -->
<!-- 可能なら dig の結果や公開情報の URL を添えてください -->

```console
$ nslookup -type=MX example.com
```

## 誤検知の心配

<!-- この文字列が他のサービスにも現れる可能性はありますか -->
