#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "../securityAnalyzer/SecurityAnalyzer.h"

namespace py = pybind11;

PYBIND11_MODULE(security_analyzer, m) {
    py::class_<SecurityAnalyzer::AnalysisResult>(m, "AnalysisResult")
        .def_readonly("is_safe", &SecurityAnalyzer::AnalysisResult::is_safe)
        .def_readonly("confidence_score", &SecurityAnalyzer::AnalysisResult::confidence_score)
        .def_readonly("detected_issues", &SecurityAnalyzer::AnalysisResult::detected_issues)
        .def_readonly("analysis_summary", &SecurityAnalyzer::AnalysisResult::analysis_summary);

    py::class_<SecurityAnalyzer>(m, "SecurityAnalyzer")
        .def(py::init<>())
        .def("analyze_text", &SecurityAnalyzer::analyzeText, "Analyze text for security issues")
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
