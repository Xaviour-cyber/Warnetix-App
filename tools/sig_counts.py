import sqlite3
con = sqlite3.connect(r"backend/data/warnetix.db")
print("TOTAL :",  con.execute("select count(*) from signatures").fetchone()[0])
print("MBZ   :",  con.execute("select count(*) from signatures where source='malwarebazaar'").fetchone()[0])
print("Kaggle:",  con.execute("select count(*) from signatures where source='kaggle'").fetchone()[0])
