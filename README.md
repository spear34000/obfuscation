# obfuscation

## Rhino JS Obfuscator 사용법

> 이 스크립트는 모듈/라이브러리가 아니라, `load('rhino-obfuscator.js')` 후 전역에 주입되는 `RhinoObfuscator` 객체를 바로 쓰는 방식입니다.

1. Rhino(또는 Java 연동이 가능한 JS 엔진)에서 로드하기:
   ```sh
   load('rhino-obfuscator.js');
   ```

2. 비밀키로 코드 난독화하기:
   ```javascript
   var secret = "change-this-secret";
   var original = "print('hello from obfuscated payload');";
   var bundle = RhinoObfuscator.obfuscate(original, secret);
   print(bundle); // 이 문자열을 저장하거나 배포
   ```

3. 필요할 때 복호화하기:
   ```javascript
   var recovered = RhinoObfuscator.deobfuscate(bundle, secret);
   print(recovered);
   ```

4. 난독화된 코드를 바로 실행하기(선택적으로 스코프 주입):
   ```javascript
   RhinoObfuscator.runObfuscated(bundle, secret, {
     print: print, // 안전한 print만 노출
     customValue: "hi"
   });
   ```

5. 시크릿을 따로 넘기지 않는 자체 포함 번들 만들기/실행:
   ```javascript
   var sealed = RhinoObfuscator.obfuscateSelfContained(original);
   // sealed 내부에 임의 생성된 시크릿이 포함되어 별도 전달 불필요
   RhinoObfuscator.runSelfContained(sealed, { print: print });
   ```
