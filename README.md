# FloraFlow – Flower Shop Management System

Role-based web app: **Customer**, **Florist/Staff**, **Delivery person** and **Administrator**,
each with their own login, backed by a real **SQLite database**, with a green theme.

## Run it
1. Install Python 3.8+ from python.org (tick "Add Python to PATH"). Nothing else to install.
2. Windows: double-click `start.bat`. Any system: run `python server.py`, then open http://localhost:8000
3. The database file `floraflow.db` is created and filled with the sample data on first run.

## Logins (password for all demo accounts: `password123`)
| Login page tab | Email | Role |
|---|---|---|
| Customer | ananya@example.com / rahul@example.com / priya@example.com | Customer |
| Customer | *(or click "Create an account")* | Customer |
| Administrator | admin@flowershop.com | Administrator |
| Staff / Delivery | staff@flowershop.com / david@flowershop.com | Florist |
| Staff / Delivery | delivery@flowershop.com / arjun@flowershop.com | Delivery |

An account only works on its own tab (a customer cannot sign in through the Administrator tab).

## What each role can do
- **Customer** – browse/filter flowers, cart, coupons, checkout, pay, track own orders, invoices. Sees only their own orders.
- **Staff** – order queue, status updates, assign couriers, restock (increase) stock.
- **Delivery** – assigned runs, start run, mark delivered (cash-on-delivery becomes Paid).
- **Administrator** – dashboard, flower/category management, users, suppliers, reports, in-app test suite, reset database.

These rules are enforced by the **server**, not just hidden in the page. The server also re-calculates prices,
totals and stock for every order, so a customer cannot tamper with them from the browser.

## Files
| File | Purpose |
|---|---|
| `index.html` | The application (screens + logic). Opens only after login. |
| `login.html` | Customer / Administrator / Staff sign-in and customer registration |
| `auth.js` | Browser side: session check, sends changes to the database, live refresh |
| `server.py` | Web server + SQLite database + login, sessions and role rules |
| `seed.json` | Sample data used to fill a new database |
| `start.bat` | Windows one-click start |

Old files `app.js`, `data.js`, `styles.css` and `server.ps1` are not used by `index.html` and can be deleted.

## Hosting (e.g. Render)
Start command `python server.py`. The app reads `PORT` automatically. To keep data permanently, attach a
persistent disk and set the environment variable `DB_PATH` to a file on that disk (e.g. `/var/data/floraflow.db`).
Change or delete the demo accounts before making the site public.

## Test cases (Table 5)
Admin menu → "Test Suite (12 TCs)". TC01, TC02 and TC12 now check the real server login and access rules.
