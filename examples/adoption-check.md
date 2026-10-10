# jev-proxy — contrôle d’adoption · adoption check · comprobación de adopción

## Français

Point de départ local, après la préparation indiquée dans le README :

```sh
npm run demo:policy
```

Comparez autorisation, refus et attente d’approbation pour un même appel MCP synthétique. Un champ manquant ne doit pas satisfaire silencieusement une règle `notEquals`.

## English

Local starting point, after the setup described in the README:

```sh
npm run demo:policy
```

Compare allow, deny and approval-pending outcomes for a synthetic MCP call. A missing field must not silently satisfy a `notEquals` rule.

## Español

Punto de partida local, después de la preparación descrita en el README:

```sh
npm run demo:policy
```

Compare permitir, denegar y pendiente de aprobación para una llamada MCP sintética. Un campo ausente no debe cumplir silenciosamente una regla `notEquals`.
## Variante synthétique · Synthetic variation · Variante sintética

```text
policy.notEquals={"field":"recipient","value":"blocked"}; call.args={}
```

FR : adaptez une copie de la fixture locale à cette situation, puis vérifiez le comportement décrit ci-dessus. Les valeurs sont illustratives, pas des résultats Jev mesurés.

EN: adapt a copy of the local fixture to this situation, then check the behavior described above. Values are illustrative, not measured Jev output.

ES: adapte una copia de la fixture local a esta situación y compruebe el comportamiento descrito arriba. Los valores son ilustrativos, no resultados Jev medidos.

## Second cas · Second case · Segundo caso

```text
rule.equals={"field":"recipient","value":"alice"}; call.args={"recipient":"bob"}
```

**FR :** Une règle d’autorisation explicite pour `alice` ne doit pas autoriser `bob`. Vérifiez aussi la route de refus dans le journal d’audit synthétique.

**EN:** An explicit allow rule for `alice` must not allow `bob`. Also inspect the denial path in the synthetic audit log.

**ES:** Una regla explícita para permitir a `alice` no debe permitir a `bob`. Revise también la ruta de rechazo en el registro de auditoría sintético.
