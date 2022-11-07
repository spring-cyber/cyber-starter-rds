package com.cyber.infrastructure.config;

import com.cyber.infrastructure.toolkit.RDSEncrypts;
import com.ulisesbocchio.jasyptspringboot.EncryptablePropertyDetector;
import com.ulisesbocchio.jasyptspringboot.EncryptablePropertyResolver;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.codec.binary.Hex;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PrivateKey;

@Configuration
public class RDSConfig {
    public static final Logger LOGGING = LoggerFactory.getLogger(RDSConfig.class);

    public static final String RDS_ENCODED_PREFIX = "encrypt:";
    private static String RDS_NO_PREFIX = Hex.encodeHexString("NOPFX:".getBytes());

    @Bean(name = "encryptablePropertyDetector")
    public EncryptablePropertyDetector encryptablePropertyDetector() {
        return new DbEncryptablePropertyDetector();
    }

    @Bean(name = "encryptablePropertyResolver")
    public EncryptablePropertyResolver encryptablePropertyResolver() {
        return new DbEncryptablePropertyResolver();
    }

    public class DbEncryptablePropertyDetector implements EncryptablePropertyDetector {

        @Override
        public boolean isEncrypted(String s) {
            if (StringUtils.isNotEmpty(s)) {
                return s.startsWith(RDS_ENCODED_PREFIX);
            }
            return false;
        }

        @Override
        public String unwrapEncryptedValue(String s) {
            return s.substring(RDS_ENCODED_PREFIX.length());
        }
    }
    public class DbEncryptablePropertyResolver implements EncryptablePropertyResolver {
        @Override
        public String resolvePropertyValue(String s) {
            if(StringUtils.isNotEmpty(s) && s.startsWith(RDS_ENCODED_PREFIX)) {
                String subPrefix = s.substring(RDS_ENCODED_PREFIX.length());
                if(StringUtils.isNotEmpty(subPrefix) && subPrefix.startsWith(RDS_NO_PREFIX)) {
                    String subStr = subPrefix.substring(RDS_NO_PREFIX.length());
                    try {
                        PrivateKey privateKey = RDSEncrypts.getPrivateKey("UMPassword");
                        byte[] subStrByte = Hex.decodeHex(subStr.toCharArray());
                        byte[] resultByte = RDSEncrypts.decryptByPrivateKey(subStrByte, privateKey);
                        String result = new String(resultByte);
                        LOGGING.info("Found {} String {} Decoder {} ...", RDS_ENCODED_PREFIX, s, result);
                        return result;
                    } catch (Exception e) {
                        LOGGING.error("Found " + RDS_ENCODED_PREFIX + " String " + s + " But Decode Error ... ", e);
                        System.exit(2);
                    }
                }
            }
            return s;
        }
    }

}
