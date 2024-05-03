package fr.fernandes.will.security.service;

import fr.fernandes.will.security.record.FirstRecordTest;
import fr.fernandes.will.security.record.SecondRecordTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

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
    void list() {
        ArrayList<String> listWithInjection = new ArrayList<String>();
        listWithInjection.add("Now a normal test");
        listWithInjection.add("Just for ;DROP TABLE user; test");
        listWithInjection.add("Now a normal test");


        ArrayList<String> listWithoutInjection = new ArrayList<String>();
        listWithoutInjection.add("Now a normal test");
        listWithoutInjection.add("Just for ;DROP TABLE user; test");
        listWithoutInjection.add("Now a normal test");

        Assertions.assertAll(() -> {
            Assertions.assertFalse(injectionService.isDataSecured(listWithInjection));
            Assertions.assertTrue(injectionService.isDataSecured(listWithoutInjection));
        });
    }
}
