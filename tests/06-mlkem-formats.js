/*
 * 06-mlkem-formats.js — ML-KEM PEM import across the three FIPS 203 CHOICE
 * forms (seed / expandedKey / both). Mirrors libVES.c/tests/06-mlkem-formats.
 *
 *   ML-KEM-PrivateKey ::= CHOICE {
 *       seed        [0] IMPLICIT OCTET STRING,
 *       expandedKey     OCTET STRING,
 *       both            SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
 *   }
 *
 * All three PEMs below encode the same underlying ML-KEM-768 key — importing
 * any of them should yield the same SubjectPublicKeyInfo. PEMs lifted
 * verbatim from libVES.c/tests/06-mlkem-formats so coverage stays parallel.
 */

if (typeof window === 'undefined' && typeof require !== 'undefined') require('./node.inc.js');

vestest.register('06-mlkem-formats', async function (t) {
    var emailVault = new libVES.Vault({ domain: t.conf.DOM, externalId: t.conf.EMAIL }, t.ves);

    var PEMS = {
        seed: '-----BEGIN PRIVATE KEY-----\n' +
            'MFQCAQAwCwYJYIZIAWUDBAQCBEKAQLTRCFO/YcqrOku68jWg46LkGyoHC9IXMTk8\n' +
            '7ESYt7ppHLVnZZtyLm6YUv/I8XuTToJB8l7lfiKzBIVfbL+N+Uc=\n' +
            '-----END PRIVATE KEY-----\n',
        expkey: '-----BEGIN PRIVATE KEY-----\n' +
            'MIIJeAIBADALBglghkgBZQMEBAIEgglkBIIJYOFchWHLEwOkZYAIBboHWf+sFKjr\n' +
            'WyyrV4y1eHa1D8s4j4yKxxPRb9DVq3XxyM+DeoUzaur2wxGUFEmEStCBNJ9XhFJH\n' +
            'YV6lqqYYglGwpTSaBPfpKmoHKzERK3I7GUc7DXBiuQDjld81W7ojy6ojKaB8rZz3\n' +
            'AXiUr9YSt0zDg7gAaGN2Z0tws1FWuJipx/vzVnojh/ccyot5zPZEd7BaXz36yAIl\n' +
            'bJ3xJu1EOkX6mIukgl6CCJSJtl4IP2thtmQoKSVlgE36hERDu+LVvSzHjTmmAwHL\n' +
            'e5BozPn1xWCWDDSGUHr3j9B1PbeKoLVQgWhoewQyJiRqU3b0qdroIK/VkCUkKqDp\n' +
            'gbxgrpoWW5nIRWooQJF0FS1iwmEcGqjVUKxhFu/oDgggy1eoaVpqo3f1K7gRFduG\n' +
            'twbrsSNLB5ZENmmUJo50dD6qScAWS/y1HZZEj61zJtCFxc1izT1URpJRMYUxZuUj\n' +
            'L0fRYNuTCBVmw/X0fIqVkY4GyG7RDRhXH6nQPNeVHqIWusPlIlwgbedRJxrVEkVF\n' +
            'HZdBMnPFHz45g50Fi272OTfLG+1gwtgbo1zmSu77tMsSSYPRjq7cui0zhaJiiyQh\n' +
            'HIcahT0leFqXz3o1BhZ5LDu6DSkykjjmJHfVJ9UivrXihJDlnbnJa6tlLTpjQyYb\n' +
            'NsSJQd3iTatAJTZ4Lh/CDfAHo8yWDiGpau7ktSA5GarVxoD5LT/LcPEjo/4WKoHk\n' +
            'p+PSlL+VzIdILWQIDJBHBWeir/N2CFyBP0Lrwa/yBnS7od5pO6pmQrpAlKIpBGgx\n' +
            'CFbhcyopluRFEtUkClCWSu5yqmn5hKqAihXBQbN4mpIVAQlEfs8px2uWid42s2C1\n' +
            'd4gllnWmfrhUSLkMB270a+DSbgdSR6XBAHA4Xd6kQt/gA/YCRalpiBDgT7V2XcNm\n' +
            'R5K4F5LBvN3FUfVJZ+sxcoaID+XUcvrVP6IqUKwmonFgh6AYBrhEF5cJEHNcMlQ8\n' +
            'FJfgV4HbkwYEDAUwW1eBbTXjkQuolZLXAyRmmYE1ii9Wts/4AnkmVGpJrQA4Or0W\n' +
            'cjUKsXVUNC6GoHXKpsT0JOHXSSJVcZP6vDv1sNpCC1mFJqKFzc+jWBtDYq5GHP+J\n' +
            'CurpTXGrw0PYVWn7WVBSaZhYadnwI0u7D6CYkSO7P2wmwW76mdy1tbXhT9c6Bskj\n' +
            'ZpNpwEmjP6IspZVZIXg8tLJCdkkSBzB7VEkwx0zXDqvWnucmBWOnxmfnEVlGULdH\n' +
            'PX8SIeWSQBkWoD72ToJQfA7UbnNXXmIcwRuQZPNRcGOsB2CASsb4gfSpvM6RteEj\n' +
            'dV+mRMSiNAOlZXZqR4x0tqBko+zYtFAQMZEFRY30SIAalUPyEwHLaOl7xHVQFlaH\n' +
            'Cl78Z81avOLjysrJmQPJLV4jgN3GtEhQeRugN/1BXElKlomZyCICvWxQbFJUZP4l\n' +
            'K4ugVQDZt7kDMrawQ7jHS5BcGNRWKMS8ldGLqVEKvBFxb+r5a6ZkHBdTuOpQj4WZ\n' +
            'BR7KWijVa09onHfhF7bGRsywiZs2YyUAFa8CLOpQL1MordMwGUj2L0HkOjg1xnQp\n' +
            'e56gmQ0pEXYobT02bM16TXRQoitZNZ83NLAxwirUAL8IfOU3jMLcwn8ssXfsT9xs\n' +
            'j44JG4LzgKL0nmVwVfcZcvpkj7BkT1KbEQuILZp5EvByO22qJhnSbLISI7y1FT8i\n' +
            'er2ZGCvIiehGnFsjE5CjCHchvhu3lzswpT4MAd6SPhUZP0h5jJ4CXLbWk/FVZvZX\n' +
            'Qe5nH8Kyw5cMuhdXQ5KJSFUECvI5n/FXyOtygdQ5hoW0H1eigMlYr4IlXtKXL9xE\n' +
            'MXfXQFs4K3xIgUY1YR4XDtlkNaQ4zm68PnWTHQzqjyuHKm3wZ7zDk3CVwPTUNDyE\n' +
            'KmPsMUmiIpNyb+sRJW1WbXxzrjxwnIiWeRcIq+JBW3cqpIrisEGWkxO0EBCyx4wS\n' +
            'KamzNF1bgUZWue9BeY5Ew5GsIGKmJXJ2HmOErIgJbGsFK1jglgAtuC8JvBqgab+c\n' +
            'Ap+5iNpGoLsjZBcJTHPkLyZTt4JyPYnopsIplmvXeKJUW6LjhKL0gUlTcZiZEOGz\n' +
            'f5Kmn/WKWyggTQnKFWX7s+lVov+ypH/KfTMBgy7QiSb3hbeTrlD2GMKBgV8ELERx\n' +
            'LMd1gQGZQL0CPVaDkHlHqWLqOXjSjmYZEv8Ky/hIx0OaCBMUzvlRwCmbAFMKO/z4\n' +
            'hbjGIG6QUJEBwOV1o/izmUegOLT0I5pkfvV3lmyQhsD3wWfByOl4VGVhH7upk+Dc\n' +
            'ePtTDOcqnsh3q12wcRayrAT1tEBFTOfsxNxmgFS1qS14j5VRZcPRWiSKPkhWRdpc\n' +
            'b3EwL/MbYX7kB9ahhSGyQfcnqhTDow0zW5cmeJjBVoSLu3KhqMp8h6enYFOFKYZW\n' +
            'L+U7KSLsX1aTfQG3l6HBI9BonamkhiooshFpBaT0Kn+5XTy3qTDHvxlbroAgolCr\n' +
            'VhWkveoMRnAghT7Zt/YMqiMpkmz5Oaxkt8GVd6kxda8KNfskvUaMECA6QwB1rIl8\n' +
            'sUzstvFAmF8khS7Vy9KLcltySRepgX72YTPGZ/d2cI+EszpRQ5qKEzQYL2AqgQZK\n' +
            'JhInP4WAZ6iLuWv5t3vWUTibnmTVG+uwusDCkWChS0a2Gd5KdtXFtX16c7QmZn64\n' +
            'VJljrW0rG8kztu0UNCYcQUXYNpAwqph3Xe7MQLOHjDoAmWhya0O3G4jETQnnzdS3\n' +
            'SEObm4ysV8NkVXKrA84Mssj6lNi1bn8DGn5sRSf6Qq27O7fwFHOZGmqQSXiztoBn\n' +
            'r3L0fb2YOx52K5IAkcIhj6zYYs2QCrWkksZZGrnJhO3Yu8ZbcD+nZbZpTauVD1u8\n' +
            'wqXKJYv1ipr6d3Xqg89HgAkHA+Emle7sGpMxoBkFSvU2A/NoWdIros0lq1XgT6yQ\n' +
            'BgtbMY56AKp5ENd3V7EYa4m6NmilbMHHSKkZhvLSqCF5sRk3CEtCEogIxhlpFS2p\n' +
            'dnn8BXDqdanzrWI3cJIMely2Lry1RhFBP1SaHAikMxJSUOVovMf1KU7ZfRzFIi5W\n' +
            'LvhiZRQVRCyhzXGIseboHZ+xQvSxkp/jn1OoX4mISjP9xWHlgI7Cb6mJFdPStj+q\n' +
            'UF5iXTbffjBa5ZUg1ZLr0w3vm5TR76S2Nabxqr/f55XmcdPZ597kb47/H0MctWdl\n' +
            'm3IubphS/8jxe5NOgkHyXuV+IrMEhV9sv435Rw==\n' +
            '-----END PRIVATE KEY-----\n',
        both: '-----BEGIN PRIVATE KEY-----\n' +
            'MIIJvgIBADALBglghkgBZQMEBAIEggmqMIIJpgRAtNEIU79hyqs6S7ryNaDjouQb\n' +
            'KgcL0hcxOTzsRJi3umkctWdlm3IubphS/8jxe5NOgkHyXuV+IrMEhV9sv435RwSC\n' +
            'CWDhXIVhyxMDpGWACAW6B1n/rBSo61ssq1eMtXh2tQ/LOI+MiscT0W/Q1at18cjP\n' +
            'g3qFM2rq9sMRlBRJhErQgTSfV4RSR2FepaqmGIJRsKU0mgT36SpqBysxEStyOxlH\n' +
            'Ow1wYrkA45XfNVu6I8uqIymgfK2c9wF4lK/WErdMw4O4AGhjdmdLcLNRVriYqcf7\n' +
            '81Z6I4f3HMqLecz2RHewWl89+sgCJWyd8SbtRDpF+piLpIJeggiUibZeCD9rYbZk\n' +
            'KCklZYBN+oREQ7vi1b0sx405pgMBy3uQaMz59cVglgw0hlB694/QdT23iqC1UIFo\n' +
            'aHsEMiYkalN29Kna6CCv1ZAlJCqg6YG8YK6aFluZyEVqKECRdBUtYsJhHBqo1VCs\n' +
            'YRbv6A4IIMtXqGlaaqN39Su4ERXbhrcG67EjSweWRDZplCaOdHQ+qknAFkv8tR2W\n' +
            'RI+tcybQhcXNYs09VEaSUTGFMWblIy9H0WDbkwgVZsP19HyKlZGOBshu0Q0YVx+p\n' +
            '0DzXlR6iFrrD5SJcIG3nUSca1RJFRR2XQTJzxR8+OYOdBYtu9jk3yxvtYMLYG6Nc\n' +
            '5kru+7TLEkmD0Y6u3LotM4WiYoskIRyHGoU9JXhal896NQYWeSw7ug0pMpI45iR3\n' +
            '1SfVIr614oSQ5Z25yWurZS06Y0MmGzbEiUHd4k2rQCU2eC4fwg3wB6PMlg4hqWru\n' +
            '5LUgORmq1caA+S0/y3DxI6P+FiqB5Kfj0pS/lcyHSC1kCAyQRwVnoq/zdghcgT9C\n' +
            '68Gv8gZ0u6HeaTuqZkK6QJSiKQRoMQhW4XMqKZbkRRLVJApQlkrucqpp+YSqgIoV\n' +
            'wUGzeJqSFQEJRH7PKcdrloneNrNgtXeIJZZ1pn64VEi5DAdu9Gvg0m4HUkelwQBw\n' +
            'OF3epELf4AP2AkWpaYgQ4E+1dl3DZkeSuBeSwbzdxVH1SWfrMXKGiA/l1HL61T+i\n' +
            'KlCsJqJxYIegGAa4RBeXCRBzXDJUPBSX4FeB25MGBAwFMFtXgW0145ELqJWS1wMk\n' +
            'ZpmBNYovVrbP+AJ5JlRqSa0AODq9FnI1CrF1VDQuhqB1yqbE9CTh10kiVXGT+rw7\n' +
            '9bDaQgtZhSaihc3Po1gbQ2KuRhz/iQrq6U1xq8ND2FVp+1lQUmmYWGnZ8CNLuw+g\n' +
            'mJEjuz9sJsFu+pnctbW14U/XOgbJI2aTacBJoz+iLKWVWSF4PLSyQnZJEgcwe1RJ\n' +
            'MMdM1w6r1p7nJgVjp8Zn5xFZRlC3Rz1/EiHlkkAZFqA+9k6CUHwO1G5zV15iHMEb\n' +
            'kGTzUXBjrAdggErG+IH0qbzOkbXhI3VfpkTEojQDpWV2akeMdLagZKPs2LRQEDGR\n' +
            'BUWN9EiAGpVD8hMBy2jpe8R1UBZWhwpe/GfNWrzi48rKyZkDyS1eI4DdxrRIUHkb\n' +
            'oDf9QVxJSpaJmcgiAr1sUGxSVGT+JSuLoFUA2be5AzK2sEO4x0uQXBjUVijEvJXR\n' +
            'i6lRCrwRcW/q+WumZBwXU7jqUI+FmQUeyloo1WtPaJx34Re2xkbMsImbNmMlABWv\n' +
            'AizqUC9TKK3TMBlI9i9B5Do4NcZ0KXueoJkNKRF2KG09NmzNek10UKIrWTWfNzSw\n' +
            'McIq1AC/CHzlN4zC3MJ/LLF37E/cbI+OCRuC84Ci9J5lcFX3GXL6ZI+wZE9SmxEL\n' +
            'iC2aeRLwcjttqiYZ0myyEiO8tRU/Inq9mRgryInoRpxbIxOQowh3Ib4bt5c7MKU+\n' +
            'DAHekj4VGT9IeYyeAly21pPxVWb2V0HuZx/CssOXDLoXV0OSiUhVBAryOZ/xV8jr\n' +
            'coHUOYaFtB9XooDJWK+CJV7Sly/cRDF310BbOCt8SIFGNWEeFw7ZZDWkOM5uvD51\n' +
            'kx0M6o8rhypt8Ge8w5NwlcD01DQ8hCpj7DFJoiKTcm/rESVtVm18c648cJyIlnkX\n' +
            'CKviQVt3KqSK4rBBlpMTtBAQsseMEimpszRdW4FGVrnvQXmORMORrCBipiVydh5j\n' +
            'hKyICWxrBStY4JYALbgvCbwaoGm/nAKfuYjaRqC7I2QXCUxz5C8mU7eCcj2J6KbC\n' +
            'KZZr13iiVFui44Si9IFJU3GYmRDhs3+Spp/1ilsoIE0JyhVl+7PpVaL/sqR/yn0z\n' +
            'AYMu0Ikm94W3k65Q9hjCgYFfBCxEcSzHdYEBmUC9Aj1Wg5B5R6li6jl40o5mGRL/\n' +
            'Csv4SMdDmggTFM75UcApmwBTCjv8+IW4xiBukFCRAcDldaP4s5lHoDi09COaZH71\n' +
            'd5ZskIbA98FnwcjpeFRlYR+7qZPg3Hj7UwznKp7Id6tdsHEWsqwE9bRARUzn7MTc\n' +
            'ZoBUtakteI+VUWXD0Vokij5IVkXaXG9xMC/zG2F+5AfWoYUhskH3J6oUw6MNM1uX\n' +
            'JniYwVaEi7tyoajKfIenp2BThSmGVi/lOyki7F9Wk30Bt5ehwSPQaJ2ppIYqKLIR\n' +
            'aQWk9Cp/uV08t6kwx78ZW66AIKJQq1YVpL3qDEZwIIU+2bf2DKojKZJs+TmsZLfB\n' +
            'lXepMXWvCjX7JL1GjBAgOkMAdayJfLFM7LbxQJhfJIUu1cvSi3JbckkXqYF+9mEz\n' +
            'xmf3dnCPhLM6UUOaihM0GC9gKoEGSiYSJz+FgGeoi7lr+bd71lE4m55k1RvrsLrA\n' +
            'wpFgoUtGthneSnbVxbV9enO0JmZ+uFSZY61tKxvJM7btFDQmHEFF2DaQMKqYd13u\n' +
            'zECzh4w6AJlocmtDtxuIxE0J583Ut0hDm5uMrFfDZFVyqwPODLLI+pTYtW5/Axp+\n' +
            'bEUn+kKtuzu38BRzmRpqkEl4s7aAZ69y9H29mDsediuSAJHCIY+s2GLNkAq1pJLG\n' +
            'WRq5yYTt2LvGW3A/p2W2aU2rlQ9bvMKlyiWL9Yqa+nd16oPPR4AJBwPhJpXu7BqT\n' +
            'MaAZBUr1NgPzaFnSK6LNJatV4E+skAYLWzGOegCqeRDXd1exGGuJujZopWzBx0ip\n' +
            'GYby0qghebEZNwhLQhKICMYZaRUtqXZ5/AVw6nWp861iN3CSDHpcti68tUYRQT9U\n' +
            'mhwIpDMSUlDlaLzH9SlO2X0cxSIuVi74YmUUFUQsoc1xiLHm6B2fsUL0sZKf459T\n' +
            'qF+JiEoz/cVh5YCOwm+piRXT0rY/qlBeYl02334wWuWVINWS69MN75uU0e+ktjWm\n' +
            '8aq/3+eV5nHT2efe5G+O/x9DHLVnZZtyLm6YUv/I8XuTToJB8l7lfiKzBIVfbL+N\n' +
            '+Uc=\n' +
            '-----END PRIVATE KEY-----\n',
    };

    var publicKeys = {};
    var FORMATS = ['seed', 'expkey', 'both'];
    for (var i = 0; i < FORMATS.length; i++) {
        var fmt = FORMATS[i];
        var ksec = t.conf.EMAIL + '!mlk-' + fmt + '-' + t.conf.NONCE;
        var objk = '//' + t.conf.DOM + '/mlk-' + fmt + '-' + t.conf.NONCE;
        var objRef = libVES.Vault.toRef(objk);
        var sectionVeskey = 'mlk-' + fmt + '-' + t.conf.NONCE;
        var captured = { fmt: fmt, ksec: ksec, objRef: objRef, veskey: sectionVeskey };

        t.head('[' + fmt + '] import ML-KEM-768 PEM (CHOICE = ' + fmt + ')');
        await t.run('import section key from PEM', async function () {
            await t.ves.setSecondaryKey({ domain: t.conf.DOM, externalId: captured.ksec }, captured.veskey, { privateKey: PEMS[captured.fmt] });
            var k = await t.ves.getSecondaryKey({ domain: t.conf.DOM, externalId: captured.ksec });
            publicKeys[captured.fmt] = await k.getField('publicKey');
        });

        t.head('[' + fmt + '] encrypt an item via the imported section key');
        await t.run('put item shared with section', async function () {
            await emailVault.item(captured.objRef).put('secret-' + captured.fmt + '-' + t.conf.NONCE, [
                { domain: t.conf.DOM, externalId: captured.ksec },
                { domain: t.conf.DOM, externalId: t.conf.EMAIL },
            ]);
        });

        t.head('[' + fmt + '] decrypt via primary path');
        var got;
        await t.run('get item', async function () { got = await emailVault.item(captured.objRef).get(); });
        await t.expect('value', 'secret-' + fmt + '-' + t.conf.NONCE, got);

        t.head('[' + fmt + '] cleanup');
        await t.run('delete item', async function () { await emailVault.item(captured.objRef).delete(); });
    }

    t.head('Public keys match across CHOICE forms');
    await t.run('seed vs expkey public match', async function () {
        if (publicKeys.seed !== publicKeys.expkey) throw new Error('seed vs expkey public key differ');
    });
    await t.run('seed vs both public match', async function () {
        if (publicKeys.seed !== publicKeys.both) throw new Error('seed vs both public key differ');
    });
});

if (typeof require !== 'undefined' && require.main === module) vestest.runFromNode(['06-mlkem-formats']);
