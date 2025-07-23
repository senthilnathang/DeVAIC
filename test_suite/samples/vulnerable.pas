program VulnerableDelphiCode;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  Data.DB,
  FireDAC.Comp.Client;

var
  // Hardcoded credentials - CWE-798
  password: string = 'admin123';
  secret: string = 'mysecret';
  pass: string = 'hardcoded';
  
  // Uninitialized variables - CWE-457
  uninitVar: Variant;
  uninitPtr: PChar;
  
  // Database components
  Query: TFDQuery;
  Connection: TFDConnection;
  
  // String variables
  userInput: string;
  fileName: string;
  
procedure UnsafeDatabaseOperations;
begin
  // SQL injection vulnerabilities - CWE-89
  Query.SQL.Text := 'SELECT * FROM users WHERE name = ' + userInput;
  Query.ExecSQL();
  
  Query.SQL.Text := Format('SELECT * FROM products WHERE id = %s', [userInput]);
  Query.Open();
end;

procedure UnsafeTypeConversions;
var
  unicodeStr: UnicodeString;
  ansiStr: AnsiString;
  wideStr: WideString;
  pChar: PChar;
  pAnsiChar: PAnsiChar;
  pWideChar: PWideChar;
begin
  // Unsafe Unicode/ANSI conversions - CWE-176
  ansiStr := AnsiString(unicodeStr);
  pAnsiChar := PAnsiChar(wideStr);
  
  // Unsafe pointer casting - CWE-704
  pChar := PChar(userInput);
  pAnsiChar := PAnsiChar(userInput);
  pWideChar := PWideChar(userInput);
end;

procedure UnsafeStringOperations;
var
  buffer: array[0..255] of Char;
  src: PChar;
  dest: PChar;
begin
  // Buffer overflow risks - CWE-120
  StrCopy(dest, src);
  StrLCopy(dest, src, 100);
  StrCat(dest, src);
  
  // Unsafe pointer arithmetic - CWE-119
  Inc(dest);
  Dec(src, 5);
end;

procedure UnsafeFormatOperations;
var
  formatStr: string;
  args: array of const;
begin
  // Format string vulnerabilities - CWE-134
  formatStr := Format('User: %s, ID: %d', args);
end;

procedure UnsafeDLLOperations;
var
  hLib: THandle;
begin
  // DLL injection risks - CWE-114
  hLib := LoadLibrary('malicious.dll');
  LoadPackage('unsafe.bpl');
  GetProcAddress(hLib, 'DangerousFunction');
end;

procedure UnsafeRegistryOperations;
var
  Registry: TRegistry;
begin
  // Registry access - CWE-250
  Registry := TRegistry.Create;
  try
    Registry.OpenKey('HKEY_LOCAL_MACHINE\Software\MyApp', True);
    Registry.WriteString('Config', 'Value');
  finally
    Registry.Free;
  end;
end;

procedure UnsafeFileOperations;
var
  handle: THandle;
  path: string;
begin
  // Path traversal vulnerabilities - CWE-22
  path := ExtractFilePath('..\..\..\windows\system32\cmd.exe');
  handle := FileOpen('..\sensitive.txt', fmOpenRead);
  handle := CreateFile('..\..\config.ini', GENERIC_READ, 0, nil, OPEN_EXISTING, 0, 0);
end;

procedure WeakCryptography;
var
  hash: string;
begin
  // Weak cryptographic algorithms - CWE-327
  hash := MD5('password');
  hash := SHA1('data');
  // DES and RC4 usage would also be detected
end;

procedure UnsafeProcessExecution;
var
  processInfo: TProcessInformation;
  startupInfo: TStartupInfo;
begin
  // Command injection risks - CWE-78
  CreateProcess(nil, PChar('cmd.exe /c ' + userInput), nil, nil, False, 0, nil, nil, startupInfo, processInfo);
  WinExec(PChar('notepad.exe ' + fileName), SW_SHOW);
  ShellExecute(0, 'open', 'cmd.exe', PChar('/c ' + userInput), nil, SW_HIDE);
end;

procedure EmptyExceptionHandling;
begin
  try
    // Some risky operation
    raise Exception.Create('Test');
  except
    // Empty exception handler - CWE-390
  end;
end;

procedure WeakRandomGeneration;
var
  randomValue: Integer;
begin
  // Weak random number generation - CWE-338
  Randomize;
  randomValue := Random(100);
end;

begin
  try
    UnsafeDatabaseOperations;
    UnsafeTypeConversions;
    UnsafeStringOperations;
    UnsafeFormatOperations;
    UnsafeDLLOperations;
    UnsafeRegistryOperations;
    UnsafeFileOperations;
    WeakCryptography;
    UnsafeProcessExecution;
    EmptyExceptionHandling;
    WeakRandomGeneration;
    
    WriteLn('Vulnerable Delphi code executed');
  except
    on E: Exception do
      WriteLn(E.ClassName, ': ', E.Message);
  end;
  
  ReadLn;
end.