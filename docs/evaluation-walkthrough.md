# Synthetic evaluation walkthrough

This walkthrough uses synthetic data and is intended for a short technical
evaluation. It is not evidence of production readiness or legal compliance.

## 1. Start the local evaluation

From a clean checkout:

```sh
./scripts/setup.sh
docker compose up --build -d
docker compose exec beacon /beacon seed-demo
```

Open [http://localhost:8787](http://localhost:8787). The generated team
credentials are written to the ignored `.env` file by `setup.sh`; there is no
repository default password.

## 2. Submit a synthetic report

1. Open the public report form.
2. Use a fictional product, version and vulnerability description.
3. Optionally attach a harmless text file containing no personal or real
   vulnerability information.
4. Save the one-time recovery token shown after submission.

The receipt and recovery flow demonstrate that a reporter can follow a case
without receiving internal notes or staff-only evidence.

## 3. Triage and communicate

Sign in as the seeded team user. Locate the case in the queue, assign it,
record severity and affected-product information, and send a clearly marked
internal note. Send a separate reporter-visible reply and confirm that the
two message types remain distinct.

Advance the synthetic case through its workflow. If CRA tracking is exercised,
record the human classification and awareness time; Beacon does not determine
legal applicability.

## 4. Review and export

Use the case history and audit view to inspect the recorded changes. Generate a
selective export and verify that it contains only the intended reporter-facing
content. Treat the full case archive as private internal material.

## 5. Stop and clean up

```sh
docker compose down
```

The named database volume persists between runs. To deliberately remove this
synthetic evaluation data, use `docker compose down -v` only after confirming
that the local database is disposable.

For a repeatable verification pass, use `./scripts/smoke.py` and the checks
listed in the root README. Do not route live vulnerability reports through
this evaluation setup.
