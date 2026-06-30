from engines.subdomain_enum import SubdomainEnum
import engines.subdomain_enum

print("Loaded from:")
print(engines.subdomain_enum.__file__)

enum = SubdomainEnum()

result = enum.enumerate("google.com")

print(result)
