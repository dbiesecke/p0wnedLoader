TOOLS=p0wnedEncrypt.exe p0wnLoaderx86.exe p0wnLoaderx64.exe p0wnShellx86.enc p0wnShellx64.enc
PASSWORD=test123!!

all: $(TOOLS)

p0wnedEncrypt.exe:
	@cli-csc /unsafe /out:p0wnedEncrypt.exe /platform:x64 "p0wnedEncrypt.cs" 

p0wnLoaderx64.exe:
	@cli-csc /unsafe /out:"p0wnLoaderx64.exe" /platform:x64 "p0wnedLoader.cs" 
p0wnLoaderx86.exe:
	@cli-csc /unsafe /out:"p0wnLoaderx86.exe" /platform:x86 "p0wnedLoader.cs" 	
p0wnShell:
	@git clone https://github.com/Cn33liz/p0wnedShell.git
p0wnShellx86.enc:
	@mono p0wnedEncrypt.exe p0wnedShellx86.exe $(PASSWORD) p0wnedShellX86.enc
p0wnShellx64.enc:	
	@mono p0wnedEncrypt.exe p0wnedShellx64.exe $(PASSWORD) p0wnedShellX64.enc
	
clean: 
	rm -fR $(TOOLS)




