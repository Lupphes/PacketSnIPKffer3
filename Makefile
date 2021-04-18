all: clean restore build

restore:
	dotnet restore ipk-sniffer/
 
build:
	dotnet build ipk-sniffer/ -o out/ -c Release
 
run:
	dotnet run --project ipk-sniffer/ipk-sniffer.csproj
clean:
	dotnet clean ipk-sniffer/
	rm -rf ./out
 
run-clean: clean restore build run 
 
