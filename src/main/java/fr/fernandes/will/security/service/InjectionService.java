package fr.fernandes.will.security.service;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import fr.fernandes.will.security.annotation.SecurityIgnore;

public class InjectionService {
    private static final String PRIMITIVE_TYPE_PACKAGE = "java.lang.";
    private static final List<String> INJECTION_REGEX;

    static {
        INJECTION_REGEX = new ArrayList<>();

        // SQL detection
        INJECTION_REGEX.add("DROP|SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DATABASE|TABLE|'|%%");
    }

    private InjectionService() {}

    /**
     * Getter for Security instance
     *
     * @return Instance of Security class
     */
    public static InjectionService getInstance() {
        return InstanceHolder.INSTANCE;
    }

    public boolean isDataSecured(Object dataToCheck) {
        try {
            // Check if class is a list
            if (dataToCheck instanceof List<?>) {
                return listDataValidity((List<?>) dataToCheck);
            }

            // Get object class
            Class<?> clazz = dataToCheck.getClass();

            // Return true if data to check is oh type primitive
            if (clazz.isPrimitive()) {
                return true;
            }


            return switch (clazz.getTypeName()) {
                    // If data is an instance of a primitive type object, return true
                case PRIMITIVE_TYPE_PACKAGE + "Boolean",
                        PRIMITIVE_TYPE_PACKAGE + "Character",
                        PRIMITIVE_TYPE_PACKAGE + "Long",
                        PRIMITIVE_TYPE_PACKAGE + "Float",
                        PRIMITIVE_TYPE_PACKAGE + "Byte",
                        PRIMITIVE_TYPE_PACKAGE + "Double",
                        PRIMITIVE_TYPE_PACKAGE + "Integer",
                        PRIMITIVE_TYPE_PACKAGE + "Short" -> true;

                    // Check string data validity
                case PRIMITIVE_TYPE_PACKAGE + "String" -> stringValidity(dataToCheck.toString());

                    // Check all custom class
                default -> checkCustomClassValidity(dataToCheck);
            };
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method check if there is a code injection in data
     *
     * @param unsecuredData not secured data
     * @return boolean for check if sql injection is detected
     */
    private boolean stringValidity(String unsecuredData) {
        Pattern pattern;
        Matcher matcher;
        for (String injectionRegex : INJECTION_REGEX) {
            // Initialize pattern
            pattern = Pattern.compile(injectionRegex);

            // Find match
            matcher = pattern.matcher(unsecuredData);

            // If match found, string value is not secured
            if (matcher.find()) {
                return false;
            }
        }

        // String value is secured
        return true;
    }

    /**
     * Check all data in List validity
     *
     * @param list list with all data to check
     * @return boolean, if data is secured or not
     */
    private boolean listDataValidity(List<?> list) {
        // Check all elements in the list
        for (Object object : list) {
            // Return false if data is not secured
            if (!isDataSecured(object)) {
                return false;
            }
        }

        // Data is secured
        return true;
    }

    /**
     * Method use reflexion for analyze data in an unknown object
     *
     * @param data class to analyze
     * @return True if all data in the object is secured, else false
     * @throws IllegalAccessException When an error occurred during data access
     */
    private boolean checkCustomClassValidity(Object data) throws IllegalAccessException {
        // Not a default class in java
        Field[] fields = data.getClass().getDeclaredFields();
        for (Field field : fields) {
            // Check if ignore annotation is present, stop the check
            if (field.isAnnotationPresent(SecurityIgnore.class)) {
                continue;
            }

            // Check if data sent is instance of a primitive type
            field.setAccessible(true);
            Object fieldValue = field.get(data);

            // Send to isDataSecured() to check all object data
            if (!isDataSecured(fieldValue)) {
                // If data is not secured, return false
                return false;
            }

            // For security, pass accessibility to false
            field.setAccessible(false);
        }

        return true;
    }

    /** Singleton instance */
    private static final class InstanceHolder {
        private static final InjectionService INSTANCE = new InjectionService();
    }
}
