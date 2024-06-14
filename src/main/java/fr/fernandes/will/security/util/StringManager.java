package fr.fernandes.will.security.util;

public class StringManager {
    private StringManager() {}

    /**
     * Remove all spaces of a string
     *
     * @param string string to remove spaces
     * @return same string without spaces
     */
    public static String removeSpaces(String string) {
        return string.trim().replace(Constants.SPACE_STRING, Constants.EMPTY_STRING);
    }
}
