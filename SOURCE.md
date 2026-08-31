# Site list sources

`sites.yaml` has exactly 400 unique real cities. Names were not invented.

## United States (300 cities)

U.S. Census Bureau, Population Division.

Annual Estimates of the Resident Population for Incorporated Places of 20,000
or More, Ranked by July 1, 2025 Population: April 1, 2020 to July 1, 2025
(file `SUB-IP-EST2025-ANNRNK`).

- Table page: https://www.census.gov/data/tables/time-series/demo/popest/2020s-total-cities-and-towns.html
- Spreadsheet: https://www2.census.gov/programs-surveys/popest/tables/2020-2025/cities/totals/SUB-IP-EST2025-ANNRNK.xlsx

The 50 `type: regional` rows are the most populous place in each of the 50 U.S.
states in that ranking (Honolulu is listed by Census as Urban Honolulu CDP).
The other U.S. rows are the next most populous places from the same file,
including Washington, D.C. as a branch (D.C. is not a state, so it is not
regional).

Census legal names are shortened to the common city name where the legal name
is a consolidated government, for example Nashville-Davidson metropolitan
government (balance) → Nashville. The place is the same Census row.

## Worldwide remainder (100 cities)

GeoNames gazetteer dump `cities15000` (populated places with population
greater than 15,000, or capitals), Creative Commons Attribution 4.0.

- Download: https://download.geonames.org/export/dump/cities15000.zip
- Admin-1 names: https://download.geonames.org/export/dump/admin1CodesASCII.txt
- Project: https://www.geonames.org/

Non-U.S. rows only. Each row is the most populous GeoNames city in its
country; the 100 countries with the largest such cities are included.

## Not in this file

No HQ, DC (data-center), or IAP rows. No coordinates. `type` is only
`regional` or `branch`.
