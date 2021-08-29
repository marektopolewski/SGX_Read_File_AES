#include "ServerFrontEnd.h"

namespace
{
static const std::string FORM_PAGE = R"(
<!doctype html>
<html lang="en">
    <head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css"
        integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh"
        crossorigin="anonymous">

    <title>GWAS IntelSGX</title>
    </head>

    <body style="margin:1rem 2rem 0 2rem;">
    <h1 style="max-width: 700px; margin-left: auto; margin-right: auto">
        Secure GWAS powered by Intel SGX
    </h1>
    <form action="analyse" method="get" style="max-width: 700px; margin-left: auto; margin-right: auto">
        <div class="form-group">
            <label for="refGen">Reference genome (path):</label>
            <input type="text" class="form-control" id="refGen" name="refGen" />
        </div>
        <div class="form-group">
            <label for="files">SAM file(s), each on a new line:</label>
            <textarea class="form-control" id="files" name="files" rows="10"
                placeholder="[example]&#10;SAMPLE_NO_1.sam&#10;SAMPLE_NO_2.sam&#10;..."></textarea>
        </div>
        <div class="form-group">
            <label for="mapq">Minimal read quality MAPQ (0-100):</label>
            <input type="number" class="form-control" id="mapq" name="mapq" min="0" max="100" />
        </div>
        <label for="roi">Region of interest:</label>
        <div class="form-group" id="roi">
            <div class="form-row" style="width: 100%;">
                <div class="form-column" style="width: 45%;">
                    <input type="number" class="form-control" id="roi_begin"
                        name="roi_begin" min="0" max="9999999999" />
                    <div class="form-helper" style="font-size: small;">First position</div>
                </div>
                <div class="form-column" style="width: 45%; margin-left: 1rem;">
                    <input type="number" class="form-control" id="roi_end"
                        name="roi_end" min="0" max="9999999999" />
                    <div class="form-helper" style="font-size: small;">Last position</div>
                </div>
            </div>
        </div>
        <div class="form-group" style="margin-left:1.5rem">
            <input class="form-check-input" type="checkbox" value="" id="return" name="return" checked />
            <label class="form-check-label" for="return">Dump output to HTTP response</label>
        </div>
        
        <button type="submit" class="btn btn-primary">Submit</button>
    </form>

    <!-- ext JS scripts -->
    <script src="https://code.jquery.com/jquery-3.4.1.slim.min.js"
        integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n"
        crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js"
        integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo"
        crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js"
        integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6"
        crossorigin="anonymous"></script>
    </body>
</html>
)";
} // unnamed namepsace

const std::string & ServerFrontEnd::formPage()
{
	return FORM_PAGE;
}
