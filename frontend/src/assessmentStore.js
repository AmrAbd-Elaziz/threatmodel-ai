export const CURRENT_ASSESSMENT_KEY =
  "threatmodel-current-assessment";

export function getCurrentAssessment() {
  const savedAssessment =
    localStorage.getItem(
      CURRENT_ASSESSMENT_KEY
    );

  if (!savedAssessment) {
    return null;
  }

  try {
    const parsedAssessment =
      JSON.parse(savedAssessment);

    if (
      !parsedAssessment ||
      !parsedAssessment.summary ||
      !parsedAssessment.architecture
    ) {
      throw new Error(
        "Invalid stored assessment."
      );
    }

    return parsedAssessment;
  } catch {
    localStorage.removeItem(
      CURRENT_ASSESSMENT_KEY
    );

    return null;
  }
}

export function saveCurrentAssessment(
  assessment
) {
  localStorage.setItem(
    CURRENT_ASSESSMENT_KEY,
    JSON.stringify(assessment)
  );

  window.dispatchEvent(
    new CustomEvent(
      "threatmodel-assessment-changed",
      {
        detail: assessment,
      }
    )
  );
}

export function clearCurrentAssessment() {
  localStorage.removeItem(
    CURRENT_ASSESSMENT_KEY
  );
}
