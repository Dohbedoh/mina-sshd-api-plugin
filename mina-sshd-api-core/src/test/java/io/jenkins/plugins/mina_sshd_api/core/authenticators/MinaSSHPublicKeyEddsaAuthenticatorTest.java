package io.jenkins.plugins.mina_sshd_api.core.authenticators;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import hudson.model.TaskListener;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyEncryptionContext;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class MinaSSHPublicKeyEddsaAuthenticatorTest {

    private static final Logger LOGGER = Logger.getLogger(MinaSSHPublicKeyEddsaAuthenticatorTest.class.getName());

    @Rule
    public JenkinsRule r = new JenkinsRule();

    @Test
    public void testE25519() throws Exception {
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator(SecurityUtils.EDDSA);
        generator.initialize(256);
        KeyPair ecKeyUser = generator.generateKeyPair();

        final SSHUserPrivateKey sshCredentials = new BasicSSHUserPrivateKey(
            CredentialsScope.GLOBAL,
            "credId",
            "doesnotmatter",
            new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(getPrivateKey(ecKeyUser)),
            "",
            "description");

        withSshdServer(
                sshdServer -> {
                    sshdServer.setPublickeyAuthenticator(
                            (s, publicKey, serverSession) -> KeyUtils.compareKeys(publicKey, ecKeyUser.getPublic()));
                },
                sshdServer -> {
                    try (SshClient sshClient = SshClient.setUpDefaultClient()) {
                        sshClient.start();
                        try (ClientSession connection = sshClient
                                .connect(sshCredentials.getUsername(), sshdServer.getHost(), sshdServer.getPort())
                                .verify(15, TimeUnit.SECONDS)
                                .getSession()) {

                            SSHAuthenticator<Object, StandardUsernameCredentials> instance =
                                    SSHAuthenticator.newInstance(connection, sshCredentials, null);
                            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
                            assertThat(instance.canAuthenticate(), is(true));
                            assertThat(instance.authenticate(TaskListener.NULL), is(true));
                            assertThat(instance.isAuthenticated(), is(true));
                            assertThat(connection.getUsername(), is(sshCredentials.getUsername()));
                        }

                    } catch (IOException | InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    private void withSshdServer(Consumer<SshServer> beforeStart, Consumer<SshServer> body) throws IOException {

        try (SshServer sshd = SshServer.setUpDefaultServer()) {
            sshd.setHost("localhost");
            sshd.setPort(0);
            sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
            sshd.setUserAuthFactories(Collections.singletonList(new UserAuthPublicKeyFactory()));

            if (beforeStart != null) {
                beforeStart.accept(sshd);
            }

            try {
                sshd.start();
                LOGGER.log(Level.INFO, "Started ssh Server");

                body.accept(sshd);

            } catch (Throwable e) {
                LOGGER.log(Level.WARNING, "Problems starting ssh server", e);
                try {
                    sshd.stop();
                } catch (Throwable t) {
                    LOGGER.log(Level.WARNING, "Problems shutting down ssh server", t);
                }
                throw e;

            } finally {

                try {
                    sshd.stop(true);
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Problems shutting down ssh server", e);
                }
            }
        }
    }

    private PublicKey readPublicKey(Path resourcePath) throws IOException {
        try (FileReader keyReader = new FileReader(resourcePath.toFile())) {
            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
            return converter.getPublicKey(publicKeyInfo);
        }
    }

    private PrivateKey readPrivateKey(Path resourcePath) throws IOException {
        try (FileReader keyReader = new FileReader(resourcePath.toFile())) {
            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());
            return converter.getPrivateKey(privateKeyInfo);
        }
    }

    private String getPrivateKey(KeyPair keyPair) throws IOException, GeneralSecurityException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(keyPair, "", new OpenSSHKeyEncryptionContext(), bos);
            return bos.toString(StandardCharsets.UTF_8);
        }
    }

    private String getPublicKey(KeyPair keyPair) throws IOException, GeneralSecurityException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            OpenSSHKeyPairResourceWriter.INSTANCE.writePublicKey(keyPair.getPublic(), "", bos);
            return bos.toString(StandardCharsets.UTF_8);
        }
    }
}
