package io.jzheaux.springsecurity.goals;

import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@RunWith(SpringRunner.class)
public class GoalControllerTests {
    @Autowired
    MockMvc mvc;

    @MockBean
    GoalRepository goals;

    @Test
    @WithMockUser(username="josh")
    public void makeWhenGoalThenIncludesUser() throws Exception {
        when(this.goals.save(any())).thenAnswer((parameters) -> parameters.getArgument(0));
        this.mvc.perform(post("/goal")
                        .content("Take Over the World")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.owner").value("josh"));
    }
}
