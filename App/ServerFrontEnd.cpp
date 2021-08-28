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

	  <body style="margin:1rem 2rem 0 2rem">
		<h1>Secure GWAS powered by Intel SGX</h1>
		<form action="analyse" method="get">
		  <div class="form-group">
			<label for="inpGen">Input genome (path):</label>
			<input type="text" class="form-control" id="inpGen" name="inpGen" />
		  </div>
		  <div class="form-group">
			<label for="refGen">Reference genome (path):</label>
			<input type="text" class="form-control" id="refGen" name="refGen" />
		  </div>
		  <div class="form-group">
			<label for="pheno">Phenotype ID:</label>
			<input type="number" class="form-control" id="pheno" name="pheno" />
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
	</html>)";
} // unnamed namepsace

const std::string & ServerFrontEnd::formPage()
{
	return FORM_PAGE;
}
