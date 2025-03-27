bcdedit -set testsigning on
# 1. For WFP testing
bcdedit.exe /set groupsize 2
bcdedit.exe /set groupaware on
shutdown.exe -r -t 0 -f
# end 1.