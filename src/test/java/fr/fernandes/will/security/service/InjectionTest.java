package fr.fernandes.will.security.service;

import java.util.ArrayList;

import fr.fernandes.will.security.record.FirstRecordTest;
import fr.fernandes.will.security.record.SecondRecordTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class InjectionTest {
    private final InjectionService injectionService = InjectionService.getInstance();

    @Test
    @DisplayName("String verification")
    void stringVerification() {
        // String with SQL injection
        Assertions.assertFalse(injectionService.isDataSecured("Just for ;DROP TABLE user; test"));

        // Valid string
        Assertions.assertTrue(injectionService.isDataSecured("Just for test"));
    }

    @Test
    @DisplayName("Primitive type verification")
    void primitiveVerification() {
        // Char
        Assertions.assertTrue(injectionService.isDataSecured('c'));

        // Boolean
        Assertions.assertTrue(injectionService.isDataSecured(true));

        // Integer
        Assertions.assertTrue(injectionService.isDataSecured(Integer.MAX_VALUE));

        // Float
        Assertions.assertTrue(injectionService.isDataSecured(Float.MAX_VALUE));

        // Long
        Assertions.assertTrue(injectionService.isDataSecured(Long.MAX_VALUE));

        // Byte
        Assertions.assertTrue(injectionService.isDataSecured(Byte.MAX_VALUE));

        // Double
        Assertions.assertTrue(injectionService.isDataSecured(Double.MAX_VALUE));

        // Short
        Assertions.assertTrue(injectionService.isDataSecured(Short.MAX_VALUE));
    }

    @Test
    @DisplayName("Record without injection")
    void recordWithoutInjection() {
        Assertions.assertTrue(injectionService.isDataSecured(new FirstRecordTest("Record without injection")));
    }

    @Test
    @DisplayName("Record with injection")
    void recordWithInjection() {
        Assertions.assertFalse(injectionService.isDataSecured(new FirstRecordTest("Just for ;DROP TABLE user; test")));
    }

    @Test
    @DisplayName("Record with annotation")
    void recordWithAnnotation() {
        Assertions.assertTrue(injectionService.isDataSecured(new SecondRecordTest("Just for ;DROP TABLE user; test")));
    }

    @Test
    @DisplayName("List detection")
    void list() {
        ArrayList<String> injection = new ArrayList<>();
        injection.add("Now a normal test");
        injection.add("Just for ;DROP TABLE user; test");
        injection.add("Now a normal test");

        ArrayList<String> regularList = new ArrayList<>();
        regularList.add("Now a normal test");
        regularList.add("Now a normal test");

        Assertions.assertAll(() -> {
            Assertions.assertFalse(injectionService.isDataSecured(injection));
            Assertions.assertTrue(injectionService.isDataSecured(regularList));
        });
    }

    @Test
    @DisplayName("HTML injection detection")
    void htmlInjection() {
        // In string
        boolean injectedString = injectionService.isDataSecured("<html>Juste for test</html>");
        boolean clearString = injectionService.isDataSecured("Juste for test");

        // In list
        ArrayList<Object> injectedList = new ArrayList<>();
        injectedList.add("Juste for test");
        injectedList.add("<html>Juste for test</html>");
        boolean injectedListIsSecured = injectionService.isDataSecured(injectedList);

        // In record
        FirstRecordTest clear = new FirstRecordTest("Just for test");
        FirstRecordTest injected = new FirstRecordTest("<html>Juste for test</html>");
        boolean dataSecured = injectionService.isDataSecured(clear);
        boolean dataInjected = injectionService.isDataSecured(injected);

        // Result
        Assertions.assertAll(() -> {
            Assertions.assertFalse(injectedString);
            Assertions.assertTrue(clearString);
            Assertions.assertFalse(injectedListIsSecured);
            Assertions.assertTrue(dataSecured);
            Assertions.assertFalse(dataInjected);
        });
    }
}
