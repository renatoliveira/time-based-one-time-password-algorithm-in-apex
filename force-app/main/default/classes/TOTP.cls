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

    public Static String ConvertStringToBase32String(String text){
        String converted = EncodingUtil.convertToHex(Blob.valueOf(text));
		String[] parts = converted.split('');
        Map<Integer,List<String>> binaryListString = new Map<Integer,List<String>>();
        Integer count = 0;
        for(String part : parts){
            binaryListString.put(count,ConvertIntegerToBinaryString(hexToInt(part),4));
            system.debug(ConvertIntegerToBinaryString(hexToInt(part),4));
            count++;
        }        
        Map<Integer,List<String>> map5Bit = convert4BitTo5Bit(binaryListString);
        return convertMap5BitsToListInteger(map5Bit,binaryListString);       
    }

    public Static List<String> ConvertIntegerToBinaryString (Integer numberInteger, Integer numeroCasas){
        List<String> binaryNumber = new List<String>();
        while(numberInteger > 1){
            binaryNumber.add(String.valueOf(math.mod(numberInteger, 2)));
            numberInteger = numberInteger /2;
        }
		binaryNumber.add(String.valueOf(numberInteger));
		binaryNumber = reverseBinaryString(binaryNumber,numeroCasas);     
        return binaryNumber;          
    }

    public Static List<String> reverseBinaryString(List<String> toReverse, Integer size){
        List<String> reverted = new List<String>();
        for(Integer i =0; i < size - toReverse.size(); i++){
            reverted.add('0');
        }
        for(Integer i =1; i <= toReverse.size(); i++){
           reverted.add(toReverse[toReverse.size() - i]);
        }
        
        return reverted;
    }

    public static final List<String> hex = '0123456789abcdef'.split('');
    
    public static Integer hexToInt(String str) {
        str = str.toLowerCase();
        String[] hexValue = str.split('');
        Integer retVal = 0;
        for(Integer i = 0; i < hexValue.size(); i++) {
            retVal = (retVal << 4) + hex.indexOf(hexValue[i]);
        }
        return retVal;
    }

    public Static Map<Integer,List<String>> convert4BitTo5Bit(Map<Integer,List<String>> map4Bit){
        Map<Integer,List<String>> map5bit = new Map<Integer,List<String>>();
        Integer sizeMap4Bit = Map4Bit.keySet().size();
        Integer count5 = 0;
        Integer count4 =0;
        while(count4 < sizeMap4Bit){
            List<String> aux1 = map4Bit.get(count4);
            List<String> aux2 = new List<String> {'0','0','0','0'};
            List<String> aux3 = new List<String> {'0','0','0','0'};
            List<String> aux4 = new List<String> {'0','0','0','0'};
            List<String> aux5 = new List<String> {'0','0','0','0'};
                        
            if(count4 + 1 < map4Bit.size()){
                aux2 = map4Bit.get(count4 + 1);
            }
            if(count4 + 2 < map4Bit.size()){
                aux3 = map4Bit.get(count4 + 2);
            }
            if(count4 + 3 < map4Bit.size()){
                aux4 = map4Bit.get(count4 + 3);
            }
            if(count4 + 4 < map4Bit.size()){
                aux5 = map4Bit.get(count4 + 4);
            }
            List<String> aux6 = new List<String>();
            aux6.addAll(aux1);
            aux6.add(aux2[0]);
            map5bit.put(count5,aux6);
            List<String> aux7 = new List<String>();
            aux7.add(aux2[1]);
            aux7.add(aux2[2]);
            aux7.add(aux2[3]);
            aux7.add(aux3[0]);
            aux7.add(aux3[1]);
            map5bit.put(count5 + 1,aux7);
            List<String> aux8 = new List<String>();
            aux8.add(aux3[2]);
            aux8.add(aux3[3]);
            aux8.add(aux4[0]);
            aux8.add(aux4[1]);
            aux8.add(aux4[2]);
            map5bit.put(count5 + 2,aux8);
            List<String> aux9 = new List<String>();
            aux9.add(aux4[3]);
            aux9.addall(aux5);
            map5bit.put(count5 + 3,aux9);
            count5 +=4;
            count4 +=5;    
        }
        return map5bit;
    }    

    public Static String convertMap5BitsToListInteger(Map<Integer,List<String>> map5Bit, Map<Integer,List<String>> map4Bit){
        String pad = '';
        Integer sizeMap4Bit = Map4Bit.keySet().size();
        Integer finalQuantum = math.mod(sizeMap4Bit*4, 40);
        Integer stringSize = (sizeMap4Bit*4 / 40) * 8;
        if(finalQuantum == 8){
            pad = '======';
            stringSize +=2;
        }
        else if(finalQuantum == 16){
            pad = '====';
            stringSize +=4;
        }
		
        else if(finalQuantum == 24){
            pad = '===';
            stringSize +=5;
        }
        else if(finalQuantum == 32){
            pad = '=';
            stringSize +=7;
        }
        
        Integer countChars = 0;
        String base32String = '';
        for(Integer i : map5Bit.keyset()){
            if(countChars ==  stringSize) {
                break;
            }    
            base32String += IntTobase32(binaryToInteger(listBinaryToString(map5Bit.get(i),5)));
            countChars++;
        }
        return base32String + pad;
    }

    public static String listBinaryToString(List<String> binaryList, Integer Size){
        String binaryString = '';
        for(Integer i = 0 ; i< Size; i++){
            binaryString += binaryList[i];
        }
        return binaryString;
    }

    public static Integer binaryToInteger(String value) {
    	Integer result;
        if(value != null && value.containsOnly('01')) {
            result = 0;
            for(String s: value.split('')) {
                result = (result << 1) | (s == '1'? 1: 0);
            }
        }
    	return result;
    }

    public static final List<String> base32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.split('');
    
    public static String IntTobase32(Integer position) {
        return base32[position];
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