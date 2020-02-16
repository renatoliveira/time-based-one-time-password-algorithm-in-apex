public class TOTP {

    public static List<String> generateCodes(String key, Long milis, Integer returnDigits, String algo) {
        List<String> steps = getSteps(milis, 1);
        List<String> result = new List<String>();

        for (String step : steps) {
            System.debug('Generating for step ' + step);
            result.add(generate(key, step, returnDigits, algo));
        }

        return result;
    }

    public static String generate(String key, String stepHex, Integer returnDigits, String algo) {
        while (stepHex.length() < 16) {
            stepHex = '0' + stepHex;
        }

        Blob msg = EncodingUtil.convertFromHex(stepHex);
        Blob k = Blob.valueOf(key);

        Blob hashBin = Crypto.generateMac(algo, msg, k);

        List<Integer> hash = blobToBytes(hashBin);

        return processBytes(hash, returnDigits);
    }

    public static String processBytes(List<Integer> hash, Integer returnDigits) {

        Integer offset = hash[hash.size() - 1] & 15;

        Integer binary =
            ((hash[offset] & 127) << 24) |
            ((hash[offset + 1] & 255) << 16) |
            ((hash[offset + 2] & 255) << 8) |
            (hash[offset + 3] & 255);

        Integer otp = Math.mod(binary, getMod(returnDigits));

        String result = otp + '';

        while (result.length() < returnDigits) {
            result = '0' + result;
        }
        return result;
    }

    private static Integer getMod(Integer digits) {
        switch on digits {
            when 6 {
                return 1000000;
            }
            when 7 {
                return 10000000;
            }
            when 8 {
                return 100000000;
            }
        }
        throw new UnsupportedOperationException('Supported digits are 6, 7 and 8.');
    }

    // steps = # of steps before and ahead (the "window")
    public static List<String> getSteps(Long timeStamp, Integer genSteps) {

        List<String> result = new List<String>();

        Long mod = Math.mod(timeStamp, 30);

        if (mod != 0L) {
            timeStamp -= mod;
        }

        Long step = timeStamp / 30;

        for (Integer i = 0 - genSteps; i <= genSteps; i++) {

            if (i < 0) {
                continue;
            }

            String hexStamp = new TOTP.XBigInteger(String.valueOf(step + i), 10).asHex();

            result.add(hexStamp);
        }
        return result;
    }

    public static List<Integer> blobToBytes(Blob input) {
        String hex = EncodingUtil.convertToHex(input);
        Integer[] byteArray = new Integer[]{};
        Integer result=0;
        String[] hexString = '0123456789abcdef'.split('');
        for (Integer i = 0; i < hex.length(); i += 2) {
            result = 16*hexString.indexOf(hex.substring(i,i+1))+hexString.indexOf(hex.substring(i+1,i+2));
            byteArray.add(result);
        }
        return byteArray;
    }

    public class XByte {
        public List<String> digits = new List<String> {
            '0' , '1' , '2' , '3' , '4' , '5' ,
            '6' , '7' , '8' , '9' , 'a' , 'b' ,
            'c' , 'd' , 'e' , 'f' , 'g' , 'h' ,
            'i' , 'j' , 'k' , 'l' , 'm' , 'n' ,
            'o' , 'p' , 'q' , 'r' , 's' , 't' ,
            'u' , 'v' , 'w' , 'x' , 'y' , 'z'
        };

        private Long numInt;
        private String numHex;

        public XByte(Long i) {
            this.numInt = i;
            this.toHex();
        }

        public XByte(String hexValue) {
            this.numHex = hexValue;
            this.toInt();
        }

        public String toHex() {
            if (this.numHex != null) {
                if (this.numHex.length() > 1) {
                    this.numHex = this.numHex.removeStart('0');
                }
                return this.numHex;
            }
            Long numcpy = Long.valueOf(this.numInt+'');
            String result = '';

            if (numcpy == 0) {
                return '0';
            }

            while (numcpy > 0) {
                Integer remainder = Integer.valueOf(Math.mod(numcpy, 16));
                result = digits[remainder] + result;
                numcpy = numcpy/16;
            }
            this.numHex = result.removeStart('0');

            return result;
        }

        public Long toInt() {
            if (this.numInt != null) {
                return this.numInt;
            }
            Long result = 0;
            List<String> positions = this.numHex.reverse().split('');

            for (Integer i = positions.size() - 1; i >= 0; i--) {
                result += (digits.indexOf(positions[i]) * Math.pow(16, i)).longValue();
            }

            this.numInt = result;
            return result;
        }
    }

    public class XBigInteger {

        private Integer base;
        private Long num;
        private String hex;
        private String numAsString;

        public XBigInteger(String asString, Integer base) {
            this.numAsString = asString;
            this.base = base;

            if (base == 16) {
                this.hex = asString;
            } else if (base == 10) {
                this.num = Long.valueOf(asString);
                this.hex = new XByte(Long.valueOf(asString)).toHex();
            } else {
                throw new UnsupportedOperationException('Only base 16 is supported for now.');
            }
        }

        public List<XByte> toByteArray() {
            List<XByte> result = new List<XByte>();
            List<String> splitted = this.numAsString.split('');

            // it is a single byte then
            if (splitted.size() <= 2) {
                return new List<XByte>{new XByte(this.numAsString)};
            }

            // if there's an odd number of bytes, the first byte will
            // be zero. For example:
            // Decimal: 910
            // Hex: 0x38E
            //          first byte  second byte
            // Binary: [0000 0011] [1000 1110]
            // XByte[] index:   0           1
            Integer offset = 0;

            if (Math.mod(splitted.size(), 2) != 0) {
                offset = 1;
                result.add(new XByte('0' + splitted[0]));
            }

            for (Integer i = offset; i < splitted.size(); i += 2) {
                result.add(new XByte(splitted[i] + splitted[i+1]));
            }

            return result;
        }

        public String asHex() {
            return this.hex;
        }
    }
}