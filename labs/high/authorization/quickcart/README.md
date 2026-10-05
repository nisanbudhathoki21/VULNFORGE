# QuickCart — HIGH Security Lab

Local authorized security-testing laboratory for VULNFORGE.

## Start

python app.py

Application:

http://127.0.0.1:9002

## Demo accounts

Customer:

alice@example.com
Alice@12345!

Admin:

admin@example.com
Admin@12345!

## Intended HIGH finding

Mass Assignment → Privilege Escalation.

Endpoint:

PATCH /api/account/profile

The endpoint intentionally accepts the privileged `role` property.

This is deliberately vulnerable and exists only for the local lab.

## Security expectations

The application validates:

- email
- name
- password
- phone
- product ID
- quantity
- inventory
- coupon
- checkout calculations

Prices and checkout totals are calculated server-side.

Do not deploy this application publicly.
