# Iranian / Persian web-app patterns

Available in 3.2.1. Rules are in `recon/core/iranian.py` and feed both **Leaks** and **PII**. No external validation or provider request is made.

| Pattern | Handling | Validation / limits |
| --- | --- | --- |
| Mobile — شماره موبایل / همراه | `09xx…`, `+98…`, `0098…`; optional spaces/hyphens | Format only; does not establish that a number exists |
| National ID — کد ملی | Ten contiguous digits | Existing Iranian checksum and repeated-digit rejection |
| Sheba — شماره شبا | `IR` + 24 digits, grouped or ungrouped | Mod-97 checksum |
| Bank card — شماره کارت | Sixteen digits, grouped or ungrouped | Known Iranian issuer-prefix catalog plus Luhn; catalog is heuristic and not exhaustive |
| Landline — تلفن ثابت | Domestic/international Iranian prefix, recognized area code, eight subscriber digits | Format only |
| Postal code — کد پستی | Ten digits, optionally `12345-67890` | Requires a nearby `کد پستی` / `کدپستی` / `postal_code` / `zip_code` label; format candidate, no postal database lookup |

Examples are shapes, not real personal records. A checksum match is not proof of identity, ownership, account existence or unauthorized disclosure.

## Localized text

- Western `0123456789`, Persian `۰۱۲۳۴۵۶۷۸۹`, Arabic-Indic `٠١٢٣٤٥٦٧٨٩`, and mixed digit sets are normalized internally.
- Persian/Arabic kaf and yeh variants are normalized for label matching.
- Common nonbreaking spaces, zero-width and directional formatting marks are handled around/grouping numbers.
- Persian characters and digits encoded as JSON `\u06xx`, decimal HTML entities, or hexadecimal entities can be recognized. Original matched text is retained for evidence; normalization does not rewrite the HTTP message.
- Plain response decoding now honors a declared charset, with UTF-8 as the default. This fixes byte-preserving Burp strings appearing as mojibake to the regex scanner. Undecodable text falls back to the original value.

## Persian parameter hints

Query/form parameter names are decoded from percent-encoded UTF-8; Persian JavaScript get/set/append names are also collected.

| Review focus | Example names |
| --- | --- |
| Access control | `شناسه_کاربر`, `شماره_سفارش`, `شناسه_حساب` |
| XSS / output handling | `جستجو`, `پیام`, `توضیحات`, `محتوا`, `عنوان` |
| Business logic | `مبلغ`, `قیمت`, `تعداد`, `تخفیف`, `نقش`, `وضعیت`, `موجودی` |
| PII | `کد_ملی`, `کد_پستی`, `شماره_کارت`, `شبا`, `تلفن`, `ایمیل` |

Hints prioritize manual review; they do not prove an IDOR, XSS or business-logic defect.
