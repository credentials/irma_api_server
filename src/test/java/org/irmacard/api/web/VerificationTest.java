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
import org.irmacard.api.common.*;
import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.info.IdemixKeyStoreDeserializer;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.info.*;
import org.irmacard.api.common.DisclosureProofResult.Status;
import org.irmacard.api.common.util.GsonUtil;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
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
	public static final String schemeManager = "irma-demo";

	public VerificationTest() {
		super(new JettyTestContainerFactory());
	}

	@BeforeClass
	public static void initializeInformation() throws InfoException {
		URI core = new File(System.getProperty("user.dir")).toURI().resolve("src/main/resources/irma_configuration/");
		DescriptionStore.initialize(new DescriptionStoreDeserializer(core));
		IdemixKeyStore.initialize(new IdemixKeyStoreDeserializer(core));
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
		AttributeDisjunctionList attrs = new AttributeDisjunctionList(1);
		attrs.add(new AttributeDisjunction("Over 12", schemeManager + ".MijnOverheid.ageLower.over12"));
		DisclosureProofRequest request = new DisclosureProofRequest(null, null, attrs);
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
		PublicKey pk = ApiConfiguration.getInstance().getJwtPublicKey();
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
		PublicKey pk = ApiConfiguration.getInstance().getJwtPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("WAITING");
	}

	@Test
	@SuppressWarnings("unused")
	public void brokenProofTest() throws InfoException, KeyManagementException {
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		Response response = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity("{\"foo\": 1}", MediaType.APPLICATION_JSON));

		assert(response.getStatus() == 400);
	}

	@Test
	@SuppressWarnings("unused")
	public void brokenJsonTest() throws InfoException, KeyManagementException {
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		Response response = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity("{\"foo\": 1", MediaType.APPLICATION_JSON));

		assert(response.getStatus() == 400);
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
		PublicKey pk = ApiConfiguration.getInstance().getJwtPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("INVALID");
	}

	@Test
	public void boundProofsTest() throws InfoException, KeyManagementException {
		IdemixCredential cred1 = getAgeLowerCredential();
		IdemixCredential cred2 = getNameCredential();

		AttributeDisjunctionList attrs = new AttributeDisjunctionList(1);
		attrs.add(new AttributeDisjunction("Over 12", schemeManager + ".MijnOverheid.ageLower.over12"));
		attrs.add(new AttributeDisjunction("Name", schemeManager + ".MijnOverheid.fullName.firstname"));
		DisclosureProofRequest request = new DisclosureProofRequest(null, null, attrs);

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
		PublicKey pk = ApiConfiguration.getInstance().getJwtPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("VALID");
	}


	public IdemixCredential getAgeLowerCredential() {
		String json = "{\"attributes\":[15082857526639144750301736801242946797623027121267335185006685001574405301693,49043383912029052625232664545907757191369101943067191274,7955827,7955827,7955827,28271],\"issuer_pk\":{\"R\":[75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251,16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766,13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840,86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187,68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513,65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387],\"S\":68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136,\"Z\":44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636,\"n\":96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321,\"systemParameters\":{\"l_e\":597,\"l_e_commit\":456,\"l_e_prime\":120,\"l_h\":256,\"l_m\":256,\"l_m_commit\":592,\"l_n\":1024,\"l_r_a\":1104,\"l_s_commit\":593,\"l_statzk\":80,\"l_v\":1700,\"l_v_commit\":2036,\"l_v_prime\":1104,\"l_v_prime_commit\":1440,\"size_a_response\":74,\"size_e\":75,\"size_e_response\":117,\"size_h\":32,\"size_m\":32,\"size_n\":128,\"size_s_response\":75,\"size_statzk\":10,\"size_v\":213,\"size_v_response\":255}},\"signature\":{\"A\":57754596103743007162317554077712292647955632619323372430311376699358835037827247010185070301722799768753483665944412995703754381359772958020436371657152294639207763426124517553168914979263952351437428926111708713599195026088579964719184410759338882894019674729159096795461372433273729903950000524356516882513,\"e\":259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929785768879240734725777032492570085933,\"v\":34468449729653120535987659411971753639691120539878910220989649793424366154958299597880330956622416643289762965359236248376135253908245027733029292503080309950744492512366602142809150473331114938768080109437893939452151434275092185352176276581653581577484965107581473780583603911225217813285161694216217976057801557114903976779395935204643956108712585043017614248898998338971306336761488620748543830311658071126251794715660124939236267816372016850789196264186416569690930966843066028640459231619803886933151812386}}";

		return GsonUtil.getGson().fromJson(json, IdemixCredential.class);
	}

	public IdemixCredential getNameCredential() {
		String json = "{\"attributes\":[15082857526639144750301736801242946797623027121267335185006685001574405301693,49043383912029052660663746765671847655054331513128464566,19825771443020146,4616047,4350330,33321172869604718],\"issuer_pk\":{\"R\":[75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251,16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766,13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840,86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187,68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513,65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387],\"S\":68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136,\"Z\":44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636,\"n\":96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321,\"systemParameters\":{\"l_e\":597,\"l_e_commit\":456,\"l_e_prime\":120,\"l_h\":256,\"l_m\":256,\"l_m_commit\":592,\"l_n\":1024,\"l_r_a\":1104,\"l_s_commit\":593,\"l_statzk\":80,\"l_v\":1700,\"l_v_commit\":2036,\"l_v_prime\":1104,\"l_v_prime_commit\":1440,\"size_a_response\":74,\"size_e\":75,\"size_e_response\":117,\"size_h\":32,\"size_m\":32,\"size_n\":128,\"size_s_response\":75,\"size_statzk\":10,\"size_v\":213,\"size_v_response\":255}},\"signature\":{\"A\":66870541023203983041978194338370586034864654001392921072816269376761161151631563676083788668555566615403764302208224343432279795287163995306652977930915755818406547894433271314468094949058009133638604235892171635651231331535832687860071659593186630339818757068319584820144290378372800998622084667446411000656,\"e\":259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930055900919311487272021636275967547779,\"v\":47819544245878396677391318787058527597070837711744501935412330973797278483065192845755627168759477622322244052219584056015150485447459509228103830296630162340481202033781879796114448561695295838789734748368637134490524694431775617371911390576491029793974892832055745347225526829066743972464899364392701117670540271955868280186386724402437919436003816511706514581120486868986074746120609137617755963609537131346216146839713326291869643458139554211142140199776024601973964174078419050837888464779042889883003455165}}";

		return GsonUtil.getGson().fromJson(json, IdemixCredential.class);
	}
}
