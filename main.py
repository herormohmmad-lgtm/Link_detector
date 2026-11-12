print("___________________________________")
print("Welcome to link detector")
print("___________________________________")

# إدخال الرابط من قبل المستخدم
link = input("Please enter your link: ").lower()

# قائمة الكلمات والأنماط الخطيرة والمشبوهة (بدون تعليقات داخلها)
dangerous_words = [
    # الكلمات المرتبطة بالحسابات البنكية والمالية
    "secure",
    "security",
    "update",
    "verify",
    "account",
    "login",
    "signin",
    "banking",
    "wallet",
    "pay",
    # الكلمات المرتبطة بالجوائز والعروض الوهمية
    "win",
    "winner",
    "prize",
    "gift",
    "free",
    "bonus",
    "reward",
]

short_link_services = ["bit.ly", "t.co", "goo.gl", "ow.ly", "tinyurl"]

# فحص الوجود
found_dangerous_word = False
for word in dangerous_words:
  if word in link:
    found_dangerous_word = True
    break

# فحص الروابط القصيرة
is_short_link = any(service in link for service in short_link_services)

# الشروط والنتائج
if "http" not in link:
  print("Error: This doesn't look like a valid link (missing http/https).")
elif found_dangerous_word:
  print("⚠️ Warning: This link might be dangerous! Contains suspicious keywords.")
elif is_short_link:
  print("⚠️ Warning: This is a shortened link. Be careful!")
else:
  print("✅ The link seems normal.")