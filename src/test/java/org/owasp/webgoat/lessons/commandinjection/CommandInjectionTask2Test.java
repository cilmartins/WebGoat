/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.commandinjection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.owasp.webgoat.lessons.commandinjection.CommandInjectionTask2.LEAKED_TOKEN;

import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.web.server.ResponseStatusException;

class CommandInjectionTask2Test {

  private CommandInjectionTask2 task;
  private WebGoatUser user;

  @BeforeEach
  void setUp() {
    var safetyService = new CommandInjectionSafetyService();
    user = new WebGoatUser("alice", "password");
    safetyService.acknowledge(user);
    task = new CommandInjectionTask2(new CommandExecutionService(), safetyService);
  }

  @Test
  void shouldBuildCommandWithPayload() {
    String command = task.buildCommand("uname -a", "; whoami");

    assertThat(command).contains("whoami");
  }

  @Test
  void shouldAllowKnownDiagnosticBaseCommand() {
    assertThat(task.buildCommand("hostname", "")).isEqualTo("hostname");
    assertThat(task.buildCommand("  WHOAMI ", "")).isEqualTo("whoami");
  }

  @Test
  void shouldFallBackToDefaultWhenBaseIsBlankOrNull() {
    String defaultBase = CommandExecutionService.isWindows() ? "ver" : "uname -a";

    assertThat(task.buildCommand("", "")).isEqualTo(defaultBase);
    assertThat(task.buildCommand(null, "")).isEqualTo(defaultBase);
  }

  @Test
  void shouldNotExecuteArbitraryBaseCommand() {
    String defaultBase = CommandExecutionService.isWindows() ? "ver" : "uname -a";

    for (String malicious :
        new String[] {"cat /etc/passwd", "uname -a; id", "hostname && id", "$(id)", "`id`"}) {
      String command = task.buildCommand(malicious, "");

      assertThat(command).isEqualTo(defaultBase);
    }
  }

  @Test
  void shouldNotRunInjectedBaseCommand() {
    AttackResult result = task.run(user, "echo INJECTED_BASE_MARKER", "", "");

    assertThat(result.getOutput()).doesNotContain("INJECTED_BASE_MARKER");
  }

  @Test
  void shouldFailWhenTokenMissing() {
    AttackResult result = task.run(user, "uname -a", "; whoami", "");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("commandinjection.task2.failure.blank");
  }

  @Test
  void shouldSucceedWhenTokenMatches() {
    boolean isWindows = System.getProperty("os.name", "").toLowerCase().contains("win");
    String payload = isWindows ? "&& echo %WEBGOAT_BUILD_TOKEN%" : "; echo $WEBGOAT_BUILD_TOKEN";

    AttackResult failedAttempt = task.run(user, "", payload, "");
    String output = failedAttempt.getOutput();
    var matcher =
        Pattern.compile(
                "WEBGOAT_BUILD_TOKEN=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")
            .matcher(output);
    if (!matcher.find()) {
      throw new IllegalStateException("Token not present in output: " + output);
    }
    String token = matcher.group(1);

    AttackResult result = task.run(user, "", payload, token);

    assertThat(result.assignmentSolved()).isTrue();
    assertThat(result.getFeedback()).isEqualTo("commandinjection.task2.success");
  }

  @Test
  void shouldRejectTokenSuffix() {
    String finalCharacter = LEAKED_TOKEN.substring(LEAKED_TOKEN.length() - 1);

    assertThat(task.matchesToken(finalCharacter)).isFalse();
  }

  @Test
  void shouldRequireSafetyAcknowledgementBeforeExecution() {
    var safetyService = new CommandInjectionSafetyService();
    var lockedTask = new CommandInjectionTask2(new CommandExecutionService(), safetyService);

    assertThatThrownBy(() -> lockedTask.run(user, "", "", ""))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining("commandinjection.safety.required");
  }
}
