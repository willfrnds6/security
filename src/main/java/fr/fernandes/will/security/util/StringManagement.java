package fr.fernandes.will.security.util;

public class StringManagement {
    private StringManagement() {
    }

    /**
     * Remove all spaces of a string
     *
     * @param string string to remove spaces
     * @return same string without spaces
     */
    public static String removeSpaces(String string) {
        return string.trim().replace(" ", Constants.EMPTY_STRING);
    }
}
