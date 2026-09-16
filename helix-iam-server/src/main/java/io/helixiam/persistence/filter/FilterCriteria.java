package io.helixiam.persistence.filter;

import java.util.Arrays;
import java.util.Objects;

public record FilterCriteria(String field, FilterOperation operation, Object... value) {

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final FilterCriteria filterCriteria = (FilterCriteria) o;
        return Objects.equals(field, filterCriteria.field) && operation == filterCriteria.operation && Arrays.equals(value, filterCriteria.value);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(field) + Objects.hash(operation) + Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "FilterCriteria{" +
                "value=" + Arrays.toString(value) +
                ", field=" + field +
                ", operation=" + operation +
                '}';
    }
}
