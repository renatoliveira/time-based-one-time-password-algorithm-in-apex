@IsTest
public class TOTPTest {

    @IsTest
    static void testXByte() {
        System.assertEquals('0', new TOTP.XByte(0).toHex(), '');
        System.assertEquals('6', new TOTP.XByte(6).toHex(), '');
        System.assertEquals('a', new TOTP.XByte(10).toHex(), '');
        System.assertEquals('f', new TOTP.XByte(15).toHex(), '');
        System.assertEquals('10', new TOTP.XByte(16).toHex(), '');
        System.assertEquals('5b', new TOTP.XByte(91).toHex(), '');

        System.assertEquals(0, new TOTP.XByte('0').toInt(), '');
        System.assertEquals(6, new TOTP.XByte('6').toInt(), '');
        System.assertEquals(10, new TOTP.XByte('a').toInt(), '');
        System.assertEquals(15, new TOTP.XByte('f').toInt(), '');
        System.assertEquals(16, new TOTP.XByte('10').toInt(), '');
        System.assertEquals(91, new TOTP.XByte('5b').toInt(), '');

        System.assertEquals('1', new TOTP.XByte(1L).toHex(), '');
    }

    @IsTest
    static void testXByteList() {
        // 91, for example, is 0x5B in hexadecimal - or just '5b' -
        // should return one item representing
        //
        // BIN: 0101 1011
        // HEX:    5    B
        TOTP.XBigInteger big = new TOTP.XBigInteger('5b', 16);
        List<TOTP.XByte> byteArray = big.toByteArray();

        System.assertEquals(1, byteArray.size(), '');
        System.assertEquals(byteArray[0].toHex(), '5b', '');
        System.assertEquals(byteArray[0].toInt(), 91, '');

        // 910 is 38e, which will result in two bytes:
        // [0000 0011] [1000 1110]

        TOTP.XBigInteger big2 = new TOTP.XBigInteger('38e', 16);
        List<TOTP.XByte> byteArray2 = big2.toByteArray();

        System.assertEquals(2, byteArray2.size(), '');
        System.assertEquals('3', byteArray2[0].toHex(), '');
        System.assertEquals('8e', byteArray2[1].toHex(), '');
        System.assertEquals(3, byteArray2[0].toInt(), '');
        System.assertEquals(142, byteArray2[1].toInt(), '');
    }

    @IsTest
    static void testOTP() {
        String k    = '12345678901234567890';
        String t    = '1';
        String mode = 'hmacsha1';

        String result = TOTP.generate(k, t, 8, mode);

        System.assertEquals('94287082', result, '');
    }

    @IsTest
    static void testOTP_many() {
        String k    = '12345678901234567890';
        Long   t    = 1L;
        String mode = 'hmacsha1';

        List<String> result = TOTP.generateCodes(k, t, 8, mode);

        System.assertEquals(2, result.size(), '');
        System.assertEquals('94287082', result[1], '');
    }
}
