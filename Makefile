clean:
	dotnet clean ipk-sniffer/
 
restore:
	dotnet restore ipk-sniffer/
 
build:
	dotnet build ipk-sniffer/ -o out/ -c Release
 
run:
	dotnet run --project ipk-sniffer/ipk-sniffer.csproj

run-clean: clean restore build run 
 
all: clean restore build