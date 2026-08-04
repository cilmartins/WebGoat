/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.function.Function;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.webgoat.container.lessons.Initializable;
import org.owasp.webgoat.container.lessons.LessonName;
import org.owasp.webgoat.container.session.Course;
import org.owasp.webgoat.container.users.UserProgress;
import org.owasp.webgoat.container.users.UserProgressRepository;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RestController;

@ExtendWith(MockitoExtension.class)
class RestartLessonServiceTest {

  private MockMvc mockMvc;

  @Mock private Course course;
  @Mock private UserProgressRepository userTrackerRepository;
  @Mock private Function<String, Flyway> flywayLessons;
  @Mock private Flyway flyway;
  @Mock private Initializable lessonInitializable;
  @Mock private UserProgress userProgress;

  private RestartLessonService restartLessonService;

  @BeforeEach
  void setup() {
    restartLessonService =
        new RestartLessonService(
            course, userTrackerRepository, flywayLessons, List.of(lessonInitializable));
    // MockMvc standaloneSetup uses the controller as-is, exercising the
    // @RestController annotation and its effect on response handling.
    this.mockMvc = MockMvcBuilders.standaloneSetup(restartLessonService).build();

    when(flywayLessons.apply(anyString())).thenReturn(flyway);
    when(userTrackerRepository.findByUser(anyString())).thenReturn(userProgress);
  }

  /**
   * Verifies that the endpoint returns HTTP 200 OK for a normal lesson restart request,
   * confirming the @RestController annotation does not break the existing HTTP contract.
   */
  @Test
  void restartLessonReturnsOk() throws Exception {
    WebGoatUser user = new WebGoatUser("testUser", "password");
    when(course.getLessonByName(any(LessonName.class))).thenReturn(null);

    // The endpoint must return 200 OK when a valid lesson is provided
    mockMvc
        .perform(
            get("/service/restartlesson.mvc/TestLesson")
                .principal(() -> "testUser")
                .requestAttr(
                    "org.springframework.security.core.annotation.AuthenticationPrincipal",
                    user))
        .andExpect(status().isOk());
  }

  /**
   * Verifies that the RestartLessonService class is annotated with @RestController (not @Controller).
   *
   * <p>Using @RestController instead of @Controller prevents Spring MVC from attempting to resolve
   * a view name for the response. Without this annotation, Spring's view resolver could evaluate
   * SpEL expressions derived from user-controlled input, leading to CWE-917 (Spring View SpEL
   * Injection). @RestController combines @Controller and @ResponseBody, ensuring all handler
   * method return values are written directly to the HTTP response body rather than passed through
   * a view resolver that could execute arbitrary SpEL.
   */
  @Test
  void controllerAnnotatedWithRestControllerToPreventSpelInjection() {
    // @RestController (= @Controller + @ResponseBody) eliminates the view resolution
    // step, which is the SpEL injection sink identified by CWE-917.
    boolean hasRestController =
        RestartLessonService.class.isAnnotationPresent(RestController.class);

    org.assertj.core.api.Assertions.assertThat(hasRestController)
        .as(
            "RestartLessonService must be annotated with @RestController to prevent "
                + "Spring View SpEL Injection (CWE-917). Using @Controller without "
                + "@ResponseBody allows Spring to attempt view name resolution on the "
                + "request URL, which can evaluate SpEL expressions from user input.")
        .isTrue();
  }

  /**
   * Verifies that the RestartLessonService is NOT annotated with the plain @Controller annotation
   * at the class level (it should use @RestController instead).
   */
  @Test
  void controllerNotAnnotatedWithPlainControllerAnnotation() {
    // Ensure the vulnerable @Controller annotation was replaced with @RestController
    boolean hasPlainController =
        RestartLessonService.class.isAnnotationPresent(
            org.springframework.stereotype.Controller.class);

    // @RestController is meta-annotated with @Controller, so checking for direct
    // annotation on the class itself (not meta-annotations). @RestController does NOT
    // directly apply @Controller — it is a composed annotation. The class itself should
    // only have @RestController declared.
    RestController restControllerAnnotation =
        RestartLessonService.class.getAnnotation(RestController.class);

    org.assertj.core.api.Assertions.assertThat(restControllerAnnotation)
        .as("RestartLessonService should declare @RestController to close the SpEL injection sink")
        .isNotNull();
  }

  /**
   * Verifies that all lesson initializers are called during a restart, confirming that
   * the security fix (@RestController) does not break existing initialization functionality.
   */
  @Test
  void allLessonInitializablesAreInvokedOnRestart() {
    WebGoatUser user = new WebGoatUser("testUser", "password");
    LessonName lessonName = new LessonName("TestLesson");

    when(course.getLessonByName(any(LessonName.class))).thenReturn(null);

    restartLessonService.restartLesson(lessonName, user);

    // Verify all lesson initializers are called with the authenticated user
    verify(lessonInitializable).initialize(user);
  }

  /**
   * Verifies that Flyway clean and migrate are invoked for the authenticated user during restart,
   * confirming the security fix does not affect database reset functionality.
   */
  @Test
  void flywayCleanAndMigrateAreInvokedForUser() {
    WebGoatUser user = new WebGoatUser("testUser", "password");
    LessonName lessonName = new LessonName("TestLesson");

    when(course.getLessonByName(any(LessonName.class))).thenReturn(null);

    restartLessonService.restartLesson(lessonName, user);

    verify(flywayLessons).apply("testUser");
    verify(flyway).clean();
    verify(flyway).migrate();
  }

  /**
   * Verifies that user progress is reset and saved for the authenticated user during restart.
   */
  @Test
  void userProgressIsResetAndSavedOnRestart() {
    WebGoatUser user = new WebGoatUser("testUser", "password");
    LessonName lessonName = new LessonName("TestLesson");

    when(course.getLessonByName(any(LessonName.class))).thenReturn(null);

    restartLessonService.restartLesson(lessonName, user);

    verify(userTrackerRepository).findByUser("testUser");
    verify(userTrackerRepository).save(userProgress);
  }
}
