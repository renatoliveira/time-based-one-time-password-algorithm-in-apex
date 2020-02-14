public class TOTP {

    public static List<String> generateCodes(String key, String milis, Integer returnDigits, String algo) {
        List<String> result = new List<String>();
        System.debug('Current time: ' + milis);

        Long numericMilis = Long.valueOf(milis);
        System.debug('Numeric: ' + numericMilis);

        Long seconds = Long.valueOf(milis) / 1000;
        System.debug('Seconds since Epoch: ' + seconds);

        Integer offset = Math.mod(Integer.valueOf(seconds), 30000);
        System.debug('Offset is ' + offset + ' miliseconds...');

        result.add(generate(key, String.valueOf(numericMilis - offset), returnDigits, algo));
        result.add(generate(key, String.valueOf(numericMilis - offset - 30000), returnDigits, algo));
        result.add(generate(key, String.valueOf(numericMilis - offset - 60000), returnDigits, algo));
        result.add(generate(key, String.valueOf(numericMilis - offset + 30000), returnDigits, algo));
        result.add(generate(key, String.valueOf(numericMilis - offset + 60000), returnDigits, algo));

        return result;
    }

    public static String generate(String key, String milis, Integer returnDigits, String algo) {
        while (milis.length() < 16) {
            milis = '0' + milis;
        }

        System.debug('Milis (string): ' + milis);
        Blob msg = Blob.valueOf(String.valueOf(milis));

        System.debug(EncodingUtil.convertToHex(msg));

        Blob k = Blob.valueOf(String.valueOf(key));

        Blob hashBin = Crypto.generateMac(algo, k, msg);

        List<Integer> hash = hexToByteList(EncodingUtil.convertToHex(hashBin));

        Integer offset = hash[hash.size() - 1] & 15;

        Integer binary =
            ((hash[offset] & 127) << 24) |
            ((hash[offset + 1] & 255) << 16) |
            ((hash[offset + 2] & 255) << 8) |
            (hash[offset + 3] & 255);

        Integer otp = Math.mod(binary, 100000000);

        String result = otp + '';

        while (result.length() < returnDigits) {
            result = '0' + result;
        }
        return result;
    }

    public static List<Integer> hexToByteList(String sourceHex) {
        List<Integer> result = new List<Integer>();
        String hex = '0123456789abcdef';
        String[] hexValue = sourceHex.split('');
        for(Integer index = 0; index < hexValue.size(); index++) {
            result.add(hex.indexOf(hexValue[index]));
        }
        return result;
    }
}