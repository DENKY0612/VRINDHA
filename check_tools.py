from vrin_SOC.tools.installer import verify_all_tools
r = verify_all_tools()
print(f'Installed: {r["installed_count"]}/{r["total"]}')
print(f'Installed tools: {r["installed"]}')
print(f'Missing: {r["missing"]}')
