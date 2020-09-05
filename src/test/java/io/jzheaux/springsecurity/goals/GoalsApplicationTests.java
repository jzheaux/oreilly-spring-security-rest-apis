package io.jzheaux.springsecurity.goals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@RunWith(SpringRunner.class)
public class GoalsApplicationTests {
	@Autowired
	MockMvc mvc;

	@Test
	public void goalsWithHttpBasicShouldReturnOk() throws Exception {
		this.mvc.perform(get("/goals")
				.with(httpBasic("user", "password")))
				.andExpect(status().isOk());
	}

	@Test
	public void goalsWithJwtShouldReturnOk() throws Exception {
		this.mvc.perform(get("/goals")
			.with(jwt()))
			.andExpect(status().isOk());
	}
}
