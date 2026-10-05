# Critical - ShopCart Authorization Lab

Intended vulnerability:

Broken Object-Level Authorization (BOLA/IDOR).

Users:

Alice:
  Bearer alice-token

Bob:
  Bearer bob-token

Orders:

  1001 -> Alice
  1002 -> Bob

Expected security test:

  Alice requests /api/orders/1002

The application intentionally returns Bob's order.
