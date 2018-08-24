/*
 * SignatureTest.java
 *
 * Copyright (c) 2016, Koen van Ingen, Radboud University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the IRMA project nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.api.web;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.jetty.JettyTestContainerFactory;
import org.irmacard.api.common.AttributeDisjunction;
import org.irmacard.api.common.AttributeDisjunctionList;
import org.irmacard.api.common.ClientQr;
import org.irmacard.api.common.IrmaSignedMessage;
import org.irmacard.api.common.disclosure.DisclosureProofResult.Status;
import org.irmacard.api.common.signatures.SignatureClientRequest;
import org.irmacard.api.common.signatures.SignatureProofRequest;
import org.irmacard.api.common.signatures.SignatureProofResult;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.*;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.credentials.info.KeyException;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.util.*;

/**
 * Test class for signature createtion and verification
 */
public class SignatureTest extends JerseyTest {
	private static final String schemeManager = "irma-demo";

	public SignatureTest() {
		super(new JettyTestContainerFactory());
	}

	@Override
	protected Application configure() {
		enable(TestProperties.LOG_TRAFFIC);
		enable(TestProperties.DUMP_ENTITY);
		return new ApiApplication();
	}

	@Test
	public void verifyTimestampedSignature() throws IOException, URISyntaxException, InterruptedException {
		String abs = "{\"signature\":[{\"c\":111250636206268739725665620127849065182474109730262416699708929341029009520229,\"A\":80222109477861669382148982897750082008374156050464050933240981280252055670027981921608184847056375959008593855212417087620975081516206761729802659925192244148433104770328739819043680524657446032330064655265810941026818120769671776905194990046276119139249949522446255129138203909563069602684867181272094479574,\"e_response\":68543722677625271384268779010233872058599281822038155702363941168058816135624383590756274399070864492562085690000760111596584669477804082,\"v_response\":2156615598575777375750469960947051609392003386208903961945101940644989820146593334657050741750598781617416324732019145794123971550803579971514016704481725146827741448886129079934764167524953086061493655301427046970845727361870113794698164342543258312453421046442267635183355667826915708018020797685606244979485821213738536281744696387438446030675153164491690963151026767998816385132818856000281910487669275214286942050618367316612504570162357003370819248783714424235209172489918554421118279169403271433897515532546606376463441247027003791523304249017725989512294021432914606145329973516878379397403199737449845132,\"a_responses\":{\"0\":14380191658127953892538416098845346335725992809781074009217073835644845224176819336145665021724669737539858966771918723845195004822417380003852852255031023261302209118302012763591,\"2\":4738933511063942806288499025208246330930371698628017703420027857621240782830084488440888625848759509784763299598646500470262956596375947403496330185726828898085727431010897337280,\"3\":2892133328682779768413410808120726939838444880261901245920814886051449579896755705053611199217914807245153114918416353513484776271620646343055161866303665349689501300764769783070,\"5\":7049054475031047167783266244672053011675456278531672242141151487142554424453742513666963698374700902826887016912627163156616311220284792447136080517738924946362793774096072816663},\"a_disclosed\":{\"1\":49043497911096929607726931703203423024551950578089278988,\"4\":3421494}}],\"nonce\":0,\"context\":0,\"message\":\"I owe you everything\",\"timestamp\":{\"Time\":1526068479,\"ServerUrl\":\"https://metrics.privacybydesign.foundation/atum\",\"Sig\":{\"Alg\":\"ed25519\",\"Data\":\"46QfF52RhHp+QxcKzk0/ZmbKxMmO7jgfBq4fVwEtedmtDr5HVirjGPzW94h4mnz9Mg/P2B8/1O98+iBRzrRGCA==\",\"PublicKey\":\"e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8=\"}}}";

		GoBridge.verifyTimestamp(GsonUtil.getGson().fromJson(abs, IrmaSignedMessage.class));
	}
}
