# Charset Converter

This Burp extension helps deal with some unusual character sets, such as UTF-16LE. It converts incoming messages to UTF-8, and retains the original charset in the X-Original-Charset header. Outgoing messages have their original charset restored.