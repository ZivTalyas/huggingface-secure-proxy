#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "../securityAnalyzer/SecurityAnalyzer.h"

namespace py = pybind11;

PYBIND11_MODULE(security_analyzer, m) {
    m.doc() = "Python bindings for the Security Analyzer";

    py::class_<AnalysisResult>(m, "AnalysisResult")
        .def_readonly("is_safe", &AnalysisResult::is_safe)
        .def_readonly("confidence_score", &AnalysisResult::confidence_score)
        .def_readonly("detected_issues", &AnalysisResult::detected_issues)
        .def_readonly("analysis_summary", &AnalysisResult::analysis_summary);

    py::class_<SecurityAnalyzer>(m, "SecurityAnalyzer")
        .def(py::init<double>(), py::arg("threshold") = 0.8,
             "Create a SecurityAnalyzer with an optional safety threshold")
        .def("set_threshold", &SecurityAnalyzer::setThreshold,
             "Set the safety threshold")
        .def("get_threshold", &SecurityAnalyzer::getThreshold,
             "Get the current safety threshold")
        .def("analyze_text", &SecurityAnalyzer::analyzeText, "Analyzes a string of text for security vulnerabilities")
        .def("analyze_pdf", [](SecurityAnalyzer& self, const std::vector<uint8_t>& data) {
            return self.analyzePDF(data);
        }, "Analyze PDF data for security issues")
        .def("is_content_safe", &SecurityAnalyzer::isContentSafe, 
             "Check if content is safe based on threshold",
             py::arg("content"), py::arg("threshold") = 0.8);

    m.def("get_version", []() {
        return std::string("1.0.0");
    }, "Get the version of the security analyzer");
}
