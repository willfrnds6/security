# Security Library for Java application

This library can check many important things for the security of your application

## Checks
- SQL injection
- Email verification

## Injection
Example:
```java
InjectionService injectionService = InjectionService.getInstance();

// Check if data in a class are secured
injectionService.isDataSecured(new MyCustomClass());

// Check if data in a string are secured
injectionService.isDataSecured("My beautifull string");
```

## Token and password
This library can generate `JWT token`, hash passwords and check them.

There is some examples:

Token generation :
```java
CredentialService credentialService = CredentialService.getInstance();
credentialService.generateToken("role=admin", "id=sd3c1s3d2c1s3c");
```
Please, use the same syntax in your code. The property name before the equal and the value are required.

Hash password :
```java
CredentialService credentialService = CredentialService.getInstance();
String hash = credentialService.hash("password");
```

Hash match :
```java
CredentialService credentialService = CredentialService.getInstance();
credentialService.checkMatch(hashValue, clearValue);
```


## Annotation
You can use `@SecurityIngnore` annotation on a property of an object if you don't want to check it.

Attention, use this annotation only in a specific case.

Example :
```java
public record MyCustomRecord(@SecurityIgnore String value) {}
```

## Thanks
This library is open source and free. If you want to do some update, please, make en PR. 
