/*
 * Copyright (c) 2015, the IRMA Team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.api.web;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.jetty.JettyTestContainerFactory;
import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.api.common.AttributeDisjunction;
import org.irmacard.api.common.DisclosureProofRequest;
import org.irmacard.api.common.DisclosureProofResult.Status;
import org.irmacard.api.common.DisclosureQr;
import org.irmacard.api.common.ServiceProviderRequest;
import org.irmacard.api.common.util.GsonUtil;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import java.io.File;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class VerificationTest extends JerseyTest {
	public VerificationTest() {
		super(new JettyTestContainerFactory());
	}

	@BeforeClass
	public static void initializeInformation() throws InfoException {
		URI core = new File(System.getProperty("user.dir")).toURI().resolve("src/main/resources/irma_configuration/");
		DescriptionStore.setCoreLocation(core);
		DescriptionStore.getInstance();
		IdemixKeyStore.setCoreLocation(core);
		IdemixKeyStore.getInstance();
	}

	@Override
	protected void configureClient(ClientConfig config) {
		config.register(GsonJerseyProvider.class);
	}

	@Override
	protected Application configure() {
		enable(TestProperties.LOG_TRAFFIC);
		enable(TestProperties.DUMP_ENTITY);
		return new ApiApplication();
	}

	public String createSession() throws InfoException {
		DisclosureProofRequest request = new DisclosureProofRequest(DescriptionStore.getInstance()
				.getVerificationDescriptionByName("NYTimes", "ageLowerOver12"));
		ServiceProviderRequest spRequest = new ServiceProviderRequest("testrequest", request, 60);

		DisclosureQr qr = target("/verification/").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(spRequest, MediaType.APPLICATION_JSON), DisclosureQr.class);

		String sessiontoken = qr.getUrl();

		assert(sessiontoken.length() > 20);
		return sessiontoken;
	}

	public void doSession(List<Integer> disclosed, Status expectedResult)
	throws InfoException, KeyManagementException {
		IdemixCredential cred = getAgeLowerCredential();
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		// Create the proof and post it
		ProofList proofs = new ProofListBuilder(request.getContext(), request.getNonce())
				.addProofD(cred, disclosed)
				.build();
		Status status = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(proofs, MediaType.APPLICATION_JSON), Status.class);
		assert(status == expectedResult);

		// Fetch the JSON web token containing the attributes
		String jwt = target("/verification/" + session + "/getproof").request(MediaType.TEXT_PLAIN).get(String.class);

		// Verify the token itself, and that the credential was valid
		PublicKey pk = TokenKeyManager.getPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals(expectedResult.name());
	}

	@Test
	public void validSessionTest() throws InfoException, KeyManagementException {
		doSession(Arrays.asList(1, 2), Status.VALID);
	}

	@Test
	public void missingAttributesTest() throws InfoException, KeyManagementException {
		doSession(Collections.singletonList(1), Status.MISSING_ATTRIBUTES);
	}

	@Test
	public void missingMetadataTest() throws InfoException, KeyManagementException {
		doSession(Arrays.asList(2, 3), Status.INVALID);
	}

	@Test
	@SuppressWarnings("unused")
	public void missingProofTest() throws InfoException, KeyManagementException {
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		// Fetch the JSON web token
		String jwt = target("/verification/" + session + "/getproof").request(MediaType.TEXT_PLAIN).get(String.class);

		// Verify the token itself, and that the credential was valid
		PublicKey pk = TokenKeyManager.getPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("WAITING");
	}

	@Test
	@SuppressWarnings("unused")
	public void brokenProofTest() throws InfoException, KeyManagementException {
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		Status status = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity("{\"foo\": 1}", MediaType.APPLICATION_JSON), Status.class);
		assert(status == Status.INVALID);

		// Fetch the JSON web token containing the attributes
		String jwt = target("/verification/" + session + "/getproof").request(MediaType.TEXT_PLAIN).get(String.class);

		// Verify the token itself, and that the credential was valid
		PublicKey pk = TokenKeyManager.getPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("INVALID");
	}

	@Test
	@SuppressWarnings("unused")
	public void brokenJsonTest() throws InfoException, KeyManagementException {
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		Status status = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity("{\"foo\": 1", MediaType.APPLICATION_JSON), Status.class);
		assert(status == Status.INVALID);

		// Fetch the JSON web token containing the attributes
		String jwt = target("/verification/" + session + "/getproof").request(MediaType.TEXT_PLAIN).get(String.class);

		// Verify the token itself, and that the credential was valid
		PublicKey pk = TokenKeyManager.getPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("INVALID");
	}

	@Test
	public void invalidProofTest()
	throws InfoException, KeyManagementException, NoSuchFieldException, IllegalAccessException {
		IdemixCredential cred = getAgeLowerCredential();
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		// Create the proof
		List<Integer> disclosed = Arrays.asList(2, 3);
		ProofList proofs = new ProofListBuilder(request.getContext(), request.getNonce())
				.addProofD(cred, disclosed)
				.build();

		// Dirty hackz0rs to invalidate the proof
		Field f = ProofD.class.getDeclaredField("A");
		f.setAccessible(true);
		f.set(proofs.get(0), BigInteger.TEN);

		Status status = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(proofs, MediaType.APPLICATION_JSON), Status.class);
		assert(status == Status.INVALID);

		// Fetch the JSON web token containing the attributes
		String jwt = target("/verification/" + session + "/getproof").request(MediaType.TEXT_PLAIN).get(String.class);

		// Verify the token itself, and that the credential was valid
		PublicKey pk = TokenKeyManager.getPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("INVALID");
	}

	@Test
	public void boundProofsTest() throws InfoException, KeyManagementException {
		IdemixCredential cred1 = getAgeLowerCredential();
		IdemixCredential cred2 = getNameCredential();

		DisclosureProofRequest request = new DisclosureProofRequest(DescriptionStore.getInstance()
				.getVerificationDescriptionByName("NYTimes", "ageLowerOver12"));
		request.getContent().add(new AttributeDisjunction("name", "MijnOverheid.fullName.firstname"));
		ServiceProviderRequest spRequest = new ServiceProviderRequest("testrequest", request, 60);

		DisclosureQr qr = target("/verification/").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(spRequest, MediaType.APPLICATION_JSON), DisclosureQr.class);

		String session = qr.getUrl();

		request = target("/verification/" + session).request(MediaType.APPLICATION_JSON).get(DisclosureProofRequest.class);

		// Create the proof and post it;
		ProofList proofs = new ProofListBuilder(request.getContext(), request.getNonce())
				.addProofD(cred1, Arrays.asList(1, 2))
				.addProofD(cred2, Arrays.asList(1, 3))
				.build();
		Status status = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(proofs, MediaType.APPLICATION_JSON), Status.class);
		assert(status == Status.VALID);

		// Fetch the JSON web token containing the attributes
		String jwt = target("/verification/" + session + "/getproof").request(MediaType.TEXT_PLAIN).get(String.class);

		// Verify the token itself, and that the credential was valid
		PublicKey pk = TokenKeyManager.getPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("VALID");
	}


	public IdemixCredential getAgeLowerCredential() {
		String json = "{\"signature\":{\"A\":11381541270047868907969985942156482861384034423688300947356002654372996737642648212561626122810080664546648389727989891700473228021121434580958514613029016583105253310437917595864601236353123143503974736107690032942291646147518594210331029706557891027583275802572566431097667134066003565980526275335698812316,\"e\":259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930341746120622899260314616124485402624,\"v\":36759352402861537895287160411971711417328622508527511003920156804740772837323625867029787120598830572821371802977831631839544370168935293620240903185776291443862348619936083919278590458720879556065914973668279481966985455401841221714390996580467906780541417568121675659902224768722494535510033285404177934673158868257969485448499232678931448034361040324065405512080918088566733721084826688689550372950258350820102726313184743857876113193595893049899708853557725849510584620650579898508724995291320042227857798971},\"issuer_pk\":{\"n\":96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321,\"Z\":44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636,\"S\":68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136,\"R\":[75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251,16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766,13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840,86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187,68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513,65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387,null],\"systemParameters\":{\"l_e\":597,\"l_e_prime\":120,\"l_h\":256,\"l_m\":256,\"l_n\":1024,\"l_statzk\":80,\"l_v\":1700,\"l_e_commit\":456,\"l_m_commit\":592,\"l_r_a\":1104,\"l_s_commit\":593,\"l_v_commit\":2036,\"l_v_prime\":1104,\"l_v_prime_commit\":1440,\"size_h\":32,\"size_n\":128,\"size_m\":32,\"size_statzk\":10,\"size_v\":213,\"size_e\":75,\"size_a_response\":74,\"size_e_response\":117,\"size_s_response\":75,\"size_v_response\":255}},\"attributes\":[71471498820662428070301127877844534129921030998354025121293940496030057247389,1100614008842,7955827,7955827,7955827,7955827]}";

		return GsonUtil.getGson().fromJson(json, IdemixCredential.class);
	}

	public IdemixCredential getNameCredential() {
		String json = "{\"signature\":{\"A\":5713536158941820492177589272130455393298636772296792935455947243883380146803656517019073813637736551085798817553106590203943410938090248761733691865714858470071544082087438457999532110098142769024792675132701661664844512507549427692600015511486705024923714262624076273863366631987841367566312733848096841219,\"e\":259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930341746120622899260314616124485402624,\"v\":51053507155639383258498236217491716617852690710209310283019554445325349512557771743603187503541942303176556007331276155814541899331404414220566099038706884356315465165477345613077994772468402717242307918611268001261036243387790724860869112166630321489070639403822655322219397039741086710699599016882836671380528172344616084048293062482643804119938702652671875274879175073260349401637684361838800182210804294897279494420226049248837613330230769245418759663307979904381187305995676222604788173500898621005405864915},\"issuer_pk\":{\"n\":96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321,\"Z\":44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636,\"S\":68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136,\"R\":[75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251,16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766,13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840,86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187,68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513,65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387,null],\"systemParameters\":{\"l_e\":597,\"l_e_prime\":120,\"l_h\":256,\"l_m\":256,\"l_n\":1024,\"l_statzk\":80,\"l_v\":1700,\"l_e_commit\":456,\"l_m_commit\":592,\"l_r_a\":1104,\"l_s_commit\":593,\"l_v_commit\":2036,\"l_v_prime\":1104,\"l_v_prime_commit\":1440,\"size_h\":32,\"size_n\":128,\"size_m\":32,\"size_statzk\":10,\"size_v\":213,\"size_e\":75,\"size_a_response\":74,\"size_e_response\":117,\"size_s_response\":75,\"size_v_response\":255}},\"attributes\":[71471498820662428070301127877844534129921030998354025121293940496030057247389,1100614008845,23036574416140583473985643890,319696691566,394104700814284069891684,7758190]}";

		return GsonUtil.getGson().fromJson(json, IdemixCredential.class);
	}
}
