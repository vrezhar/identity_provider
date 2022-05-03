package am.ysu.identity.jwt;

import am.ysu.identity.util.RSAKeyUtils;

import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;

public class TestingKeyHolder
{
    private TestingKeyHolder(){}

    private final static String privateKeyString = "-----BEGIN PRIVATE KEY-----" +
            "MIIJRQIBADANBgkqhkiG9w0BAQEFAASCCS8wggkrAgEAAoICAQC0/Wb8F3zu3m+L\n" +
            "C6BIxE/OkrMMiW2gFRrur7cMotJwY3ms2SJJ86VvVR2q8m9+zFvw103mS5xTIOAI\n" +
            "3TR6i2QuC1GLh8kVThrJJGIOADrs+JRXk0AMmQskR7JSKRXID4ctTgYsBzHGussA\n" +
            "hZloCAICt/RLxq5zvr7pAxLidbG59qFmbxFnCeGr0bbS5uzlmNBpIwD+wpcKmlK5\n" +
            "QN1LjpbawQJmS5EyNPyDjO9+XVBMfzDbphUNyZn29Tr8FDpV4wwWSefPXmPqBxBR\n" +
            "GENbLK/FycxggyGmI0pfZnuo/iz4SVHaeqSdO4ewErxwUfZA5WeHn0OxbJpTwI4Q\n" +
            "GhTuLdTjMRFr7njMaI4/oFBupsj7cPI7AFs334MPngEAFBZo9+Sys4OOZ70M3k0U\n" +
            "Zb8002eBrQW1zkEOyhJgEUnBIc/V0JVultz8pnACMwiJ8GNFeyuIhYiNP/5DOfGP\n" +
            "WpVbicO7NmsV11WQYaJ1XY8IiPdds9L0rXm2TCYg+6utfVgMjD4fJ8LG4sLy8f37\n" +
            "GVuIpbSNfOr4BshLw1V67Ki2VA+8w34Qa93X5DqDlnQPVyh6lC+paiZocF4W/5DG\n" +
            "HlqdluykBD2ULr/dSf3DTz44yWERBflWRxPuPuT+iqdhOhVb/Tnbu7Ri/laB1nV/\n" +
            "gquThe+F+caKaKUfKko+wzcgCxm4IwIDAQABAoICAQCiMxrRP4eCVywls3Sg4fYX\n" +
            "zhbSXHM3bNKnKChnFaB8glmwEyQMnGMdpG0jH4PWYfTfoUS55/cf9K1ypDN8w2Ez\n" +
            "dodNAZKvGkEdFBMgMwqcBqaC2X8kCyAWEn737MQNeAUQEAWt/YCZdhupyxFRTyPm\n" +
            "Jc+0/UioiEB1eIC7HPj7DNFWiKFS82MgZaBv3+5cURgtsOYaam+MXANY7I2mQhJl\n" +
            "12V8IartENlgV7TmTWBCPhaeMnhZ09u8m8eR09r3z7OsYe1yRUhLmqr/0jvDAQhB\n" +
            "vHkB4WMNjkD/wEuAhtHsbWEC6LiQBKK0pAXmrz1+qVigDZZP8mFYP4/RVF5/melX\n" +
            "dB4sKkHUoZESh3MCHErYP6Jjq7op7PQq/ZdfmtzZUZVHTST7QRTjgjiw/KLztgmt\n" +
            "vzWpM+vJM6hYgKMVzpLCo0HVEe+QeQ8MTk7zvSPVmFFWYYmEjrVbEBv6dwjTQeUq\n" +
            "zo2iSx7+kVUh8nIE65HAybRI1cGvyduZ5JYjq3VyBz1USOroHUGHgCN3A3SBqL5g\n" +
            "OqvW/c3YcurLHFT7x+mLUS4RHIIYwjGifzUxj4Zth0acu8v8WREizVYjN9ZG9Nnm\n" +
            "KmZ0HAujc4z0Qx38veMmjZ5jD5SFZVdalNQE0iwT7oMgFfx6+WGGcKULLjb/y9Za\n" +
            "+aej7W8Qm40/PJs7FoBheQKCAQEA4KXK+yYg0P9W25JUTsFdmCwj6kJqVtDJz09w\n" +
            "wz3qOFcPciiL7FU/bIUHUNFnqjHrcL9y0tRCg5ezuNdctSU629odPsACQfj4V7Vl\n" +
            "hLocK1auY2IdRoOWOAn9mghpHeAfcGjrMbQXDsnqXQAJYx+TkFwtMoSgUpJgzsEK\n" +
            "W8j3SvYmaP+rf13/szweuVwKT8h+a5eNZuvrTTuyh45eybK7piJFmmnpMki9wmvE\n" +
            "Oe5sRi2ZFon8YnuMueXq026VdfoN3S7DsD83lSh2pRPjqmycJGQZeeNd5S8muBU/\n" +
            "LfNH6XKmFbRsvPf1fs8/4OxvkKbLyYEezMv2Moe+4lLi+7bIpQKCAQEAzj/OFl8O\n" +
            "50jfhF7v0an/dln0Iz9xv27AjvImkhbWQHWfKjxV8lmB+055BhMfnnqJx1vrE9jN\n" +
            "RYJZJGa8M53/vghAezqBrf5/MQz7+uTnKdY+a0oqUkZyR9Fsst8morhETL4wWEr+\n" +
            "gKTlOrH3Cb5nJnie39iaicz9hgEJF3xF6ITTXkAzpwjJTp5m7y8FNd0YdMT77qiF\n" +
            "KIg3A5gFPEaPdC/MbasFXQxTzh1XtkmHcFmGi8qonArFhbkmmAREXq480K/3ewnY\n" +
            "HBJg/TKaAakWlf16N0K8RPWow+AAuoVneoM92vtZwI8BN05Bdzjo3itQyCkmzmaO\n" +
            "bDq8Q8D0w2zbJwKCAQEAvSHYauoG5u6SqfngkQ2rRtqiwi94Z+8QeUFgpoASGazy\n" +
            "jCIm66o545t8NUaYCGpO1nXYrjeWaEPoQ87NdpUJoN9Zj+MIA5MhQnauKbimzrYD\n" +
            "zBhmnV9bsYJ3yJ8cINL4pSMwIICGiSTl87Z8ML/89KUmSEnw0JP8fRV5Kx1fVfU3\n" +
            "EV9ve6QgCz6qf1RGOjWKefr2SZiGWlfQTuBGXXnlElH4V7CjbHphiLZCVqOs9Mif\n" +
            "AqLZofBy4m/37FpF6zXDRlyA1HnkyedvPDwqiOk37Et6R2xtOO8hogoBTyZrfNfR\n" +
            "jKSCh/Ya8dB671sf8qD7IYNb8wAlHxW6V8GA6HtTIQKCAQEAmrWx2YYkn8lCIQE1\n" +
            "04g5YIXJZEdLA9YICzIJTLxkqqWQZxYrQkdyARi0H6JorXAtuaVxiMmv8Nv+Ehge\n" +
            "RHnYRKvb8pPIgsPMlPawbVsXK4LR/5j6dgzx3H1zlBlf2d9vHEHt8c0Pa2BFsumb\n" +
            "7Wst5OXGBxNrmMJzyfks4LkPl4NLKf/uvvUQTDD19aTHu8fFeJHqiPNQLz8+RSvb\n" +
            "gYNMSFMyfXEz7MA6fPn1uX8eYWBGVMYIBETwNYbVNGK/Bmacp83XTivsN+Jxbnxu\n" +
            "maBEmO4ypxEgOHotxgBZi5BWNsgLth+lC5Q5zUqeQNgnlb/YMMztlxXG79h/MDOl\n" +
            "ZpJZMQKCAQEAonIbf7+FXxGbkAcqYN22/umRcvp+gxNUhlaechY0PcrnXgn+CiYB\n" +
            "XsEeVSAsw1jY82mD4j5ZupbalAbhJmlZSTAfLit5IyWJYPcgjAUDSjwXQ+tD7lIu\n" +
            "A80xfrBW1krZ8LYvrIVT1SQA084OrnR587EWPHkmQ7YrNOsroDXLBpZuhph8ZYYW\n" +
            "jb2fmWjqF3EC/FpFW7oJiRiHrhJAHgYU3VkFe6TUfVT3eV4oJiE8Fo5SRpqWA+w4\n" +
            "TiwTmtOX7QP8Y8xnUnXHkZNTjxAusg+n4pNW5a3lO/Fxa4+WNSxqqIPzfL+XmvH6\n" +
            "w90NLfUO+lFJZsLCHJt6Ww0sISbcHqw58Q==\n" +
            "-----END PRIVATE KEY-----";
    private final static String publicKeyString = "-----BEGIN PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtP1m/Bd87t5viwugSMRPzpKzDIltoBUa7q+3DKLScGN5rNkiSfOlb1UdqvJvfsxb8NdN5kucUyDgCN00eotkLgtRi4fJFU4aySRiDgA67PiUV5NADJkLJEeyUikVyA+HLU4GLAcxxrrLAIWZaAgCArf0S8auc76+6QMS4nWxufahZm8RZwnhq9G20ubs5ZjQaSMA/sKXCppSuUDdS46W2sECZkuRMjT8g4zvfl1QTH8w26YVDcmZ9vU6/BQ6VeMMFknnz15j6gcQURhDWyyvxcnMYIMhpiNKX2Z7qP4s+ElR2nqknTuHsBK8cFH2QOVnh59DsWyaU8COEBoU7i3U4zERa+54zGiOP6BQbqbI+3DyOwBbN9+DD54BABQWaPfksrODjme9DN5NFGW/NNNnga0Ftc5BDsoSYBFJwSHP1dCVbpbc/KZwAjMIifBjRXsriIWIjT/+Qznxj1qVW4nDuzZrFddVkGGidV2PCIj3XbPS9K15tkwmIPurrX1YDIw+HyfCxuLC8vH9+xlbiKW0jXzq+AbIS8NVeuyotlQPvMN+EGvd1+Q6g5Z0D1coepQvqWomaHBeFv+Qxh5anZbspAQ9lC6/3Un9w08+OMlhEQX5VkcT7j7k/oqnYToVW/0527u0Yv5WgdZ1f4Krk4XvhfnGimilHypKPsM3IAsZuCMCAwEAAQ==-----END PUBLIC KEY-----";
    private static KeyPair testingKeyPair;

    public static KeyPair getTestingKeyPair() throws InvalidKeySpecException
    {
        if(testingKeyPair == null){
            testingKeyPair = new KeyPair(
                    RSAKeyUtils.getPublicKey(publicKeyString),
                    RSAKeyUtils.getPrivateKey(privateKeyString)
            );
        }
        return testingKeyPair;
    }
}
